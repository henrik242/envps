/*

 MIT License

 Copyright © 2021-2023 Samuel Venable
 Copyright © 2021-2023 devKathy

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.

*/

#include <algorithm>
#include <iostream>

#include "process.hpp"

#if defined(_WIN32)
  #include <shlwapi.h>
  #include <objbase.h>
  #include <tlhelp32.h>
  #include <winternl.h>
  #include <psapi.h>
#elif (defined(__APPLE__) && defined(__MACH__))
  #include <sys/sysctl.h>
#elif (defined(__FreeBSD__) || defined(__DragonFly__) || defined(__OpenBSD__))
  #include <sys/param.h>
  #include <sys/sysctl.h>
  #include <sys/user.h>
  #include <kvm.h>
#elif defined(__NetBSD__)
  #include <sys/param.h>
  #include <sys/sysctl.h>
  #include <kvm.h>
#elif defined(__sun)
  #include <kvm.h>
  #include <sys/param.h>
  #include <sys/time.h>
  #include <sys/proc.h>
#endif

#if (defined(_WIN32) && defined(_MSC_VER))
  #pragma comment(lib, "ntdll.lib")
#endif

namespace {

  #if defined(_WIN32)
    void message_pump() {
      MSG msg;
      while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
      }
    }
    HANDLE open_process_with_debug_privilege(ngs::ps::NGS_PROCID proc_id) {
      HANDLE proc = nullptr;
      HANDLE hToken = nullptr;
      LUID luid;
      TOKEN_PRIVILEGES tkp;
      if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
          tkp.PrivilegeCount = 1;
          tkp.Privileges[0].Luid = luid;
          tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
          if (AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), nullptr, nullptr)) {
            proc = OpenProcess(PROCESS_ALL_ACCESS, false, proc_id);
          }
        }
        CloseHandle(hToken);
      }
      if (!proc) {
        proc = OpenProcess(PROCESS_ALL_ACCESS, false, proc_id);
      }
      return proc;
    }

    std::vector<wchar_t> env_from_proc(HANDLE proc) {
      std::vector<wchar_t> buffer;
      PEB peb;
      SIZE_T nRead = 0;
      ULONG len = 0;
      PROCESS_BASIC_INFORMATION pbi;
      RTL_USER_PROCESS_PARAMETERS upp;
      NTSTATUS status = NtQueryInformationProcess(proc, ProcessBasicInformation, &pbi, sizeof(pbi), &len);
      ULONG error = RtlNtStatusToDosError(status);
      if (error) return buffer;
      ReadProcessMemory(proc, pbi.PebBaseAddress, &peb, sizeof(peb), &nRead);
      if (!nRead) return buffer;
      ReadProcessMemory(proc, peb.ProcessParameters, &upp, sizeof(upp), &nRead);
      if (!nRead) return buffer;
      len = (ULONG)upp.EnvironmentSize;
      buffer.resize(len / 2 + 1);
      ReadProcessMemory(proc, upp.Environment, &buffer[0], len, &nRead);
      if (!nRead) return buffer;
      buffer[len / 2] = L'\0';
      return buffer;
    }
  #endif

  #if (defined(__APPLE__) && defined(__MACH__))
    std::vector<std::string> env_from_proc_id(ngs::ps::NGS_PROCID proc_id) {
      std::vector<std::string> vec;
      std::size_t len = 0;
      int argmax = 0, nargs = 0;
      char *procargs = nullptr, *sp = nullptr, *cp = nullptr;
      int mib[3];
      mib[0] = CTL_KERN;
      mib[1] = KERN_ARGMAX;
      len = sizeof(argmax);
      if (sysctl(mib, 2, &argmax, &len, nullptr, 0)) {
        std::cerr << "Unaccessible or missing PID: " << proc_id << "\n";
        return vec;
      }
      procargs = (char *)malloc(argmax);
      if (!procargs) {
        std::cerr << "Unaccessible or missing PID: " << proc_id << "\n";
        return vec;
      }
      mib[0] = CTL_KERN;
      mib[1] = KERN_PROCARGS2;
      mib[2] = proc_id;
      len = argmax;
      if (sysctl(mib, 3, procargs, &len, nullptr, 0)) {
        std::cerr << "Unaccessible or missing PID: " << proc_id << "\n";
        free(procargs);
        return vec;
      }
      memcpy(&nargs, procargs, sizeof(nargs));
      cp = procargs + sizeof(nargs);
      for (; cp < &procargs[len]; cp++) {
        if (*cp == '\0') break;
      }
      if (cp == &procargs[len]) {
        free(procargs);
        return vec;
      }
      for (; cp < &procargs[len]; cp++) {
        if (*cp != '\0') break;
      }
      if (cp == &procargs[len]) {
        free(procargs);
        return vec;
      }
      sp = cp;
      int i = 0;
      while ((*sp != '\0' || i < nargs) && sp < &procargs[len]) {
        if (i >= nargs) {
          vec.push_back(sp);
        }
        sp += strlen(sp) + 1;
        i++;
      }
      free(procargs);
      return vec;
    }

  #endif
} // anonymous namespace

namespace ngs::ps {

  std::vector<std::string> environ_from_proc_id(NGS_PROCID proc_id) {
    std::vector<std::string> vec;
    if (proc_id < 0) {
      std::cerr << "Illegal PID: " << proc_id << "\n";
      return vec;
    }

    #if defined(_WIN32)
      HANDLE proc = open_process_with_debug_privilege(proc_id);
      if (proc == nullptr) {
        std::cerr << "Unaccessible or missing PID: " << proc_id << "\n";
        return vec;
      }

      std::vector<wchar_t> buffer = env_from_proc(proc);
      int i = 0;
      if (!buffer.empty()) {
        while (buffer[i] != L'\0') {
          message_pump();
          vec.push_back(narrow(&buffer[i]));
          i += (int)(wcslen(&buffer[0] + i) + 1);
        }
      }
      CloseHandle(proc);

    #elif (defined(__APPLE__) && defined(__MACH__))
      vec = env_from_proc_id(proc_id);

    #elif (defined(__linux__) || defined(__ANDROID__))
      FILE *file = fopen(("/proc/" + std::to_string(proc_id) + "/environ").c_str(), "rb");
      if (file) {
        char *env = nullptr;
        std::size_t size = 0;
        while (getdelim(&env, &size, 0, file) != -1) {
          vec.push_back(env);
        }
        if (env) free(env);
        fclose(file);
      } else {
        std::cerr << "Unaccessible or missing PID: " << proc_id << "\n";
      }

    #elif (defined(__FreeBSD__) || defined(__DragonFly__))
      int cntp = 0;
      kvm_t *kd = nullptr;
      kinfo_proc *proc_info = nullptr;
      const char *nlistf = "/dev/null";
      const char *memf   = "/dev/null";
      kd = kvm_openfiles(nlistf, memf, nullptr, O_RDONLY, nullptr);
      if (!kd) return vec;
      if ((proc_info = kvm_getprocs(kd, KERN_PROC_PID, proc_id, &cntp))) {
        char **env = kvm_getenvv(kd, proc_info, 0);
        if (env) {
          for (int i = 0; env[i]; i++) {
            vec.push_back(env[i]);
          }
        }
      } else {
        std::cerr << "Unaccessible or missing PID: " << proc_id << "\n";
      }
      kvm_close(kd);

    #elif defined(__NetBSD__)
      int cntp = 0;
      kvm_t *kd = nullptr;
      kinfo_proc2 *proc_info = nullptr;
      kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
      if (!kd) return vec;
      if ((proc_info = kvm_getproc2(kd, KERN_PROC_PID, proc_id, sizeof(struct kinfo_proc2), &cntp))) {
        char **env = kvm_getenvv2(kd, proc_info, 0);
        if (env) {
          for (int i = 0; env[i]; i++) {
            vec.push_back(env[i]);
          }
        }
      } else {
        std::cerr << "Unaccessible or missing PID: " << proc_id << "\n";
      }
      kvm_close(kd);

    #elif defined(__OpenBSD__)
      int cntp = 0;
      kvm_t *kd = nullptr;
      kinfo_proc *proc_info = nullptr;
      kd = kvm_openfiles(nullptr, nullptr, nullptr, KVM_NO_FILES, nullptr);
      if (!kd) return vec;
      if ((proc_info = kvm_getprocs(kd, KERN_PROC_PID, proc_id, sizeof(struct kinfo_proc), &cntp))) {
        char **env = kvm_getenvv(kd, proc_info, 0);
        if (env) {
          for (int i = 0; env[i]; i++) {
            vec.push_back(env[i]);
          }
        }
      } else {
        std::cerr << "Unaccessible or missing PID: " << proc_id << "\n";
      }
      kvm_close(kd);

    #elif defined(__sun)
      kvm_t *kd = nullptr;
      char **env = nullptr;
      proc *proc_info = nullptr;
      user *proc_user = nullptr;
      kd = kvm_open(nullptr, nullptr, nullptr, O_RDONLY, nullptr);
      if (!kd) return vec;
      if ((proc_info = kvm_getproc(kd, proc_id))) {
        if ((proc_user = kvm_getu(kd, proc_info))) {
          if (!kvm_getcmd(kd, proc_info, proc_user, nullptr, &env)) {
            for (int i = 0; env[i]; i++) {
              vec.push_back(env[i]);
            }
            free(env);
          }
        }
      } else {
        std::cerr << "Unaccessible or missing PID: " << proc_id << "\n";
      }
      kvm_close(kd);
    #endif

    vec.erase(std::remove_if(vec.begin(), vec.end(), [](const std::string &s) {
      return s.find('=') == std::string::npos;
    }), vec.end());
    return vec;
  }

} // namespace ngs::ps
