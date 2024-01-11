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

#include <unordered_map>
#include <algorithm>
#include <mutex>
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
  #include <libproc.h>
#elif (defined(__linux__) || defined(__ANDROID__))
  #include <dirent.h>
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

  void message_pump() {
    #if defined(_WIN32)
      MSG msg;
      while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
      }
    #endif
  }

  std::vector<std::string> string_split_by_first_equals_sign(std::string str) {
    std::size_t pos = 0;
    std::vector<std::string> vec;
    if ((pos = str.find_first_of("=")) != std::string::npos) {
      vec.push_back(str.substr(0, pos));
      vec.push_back(str.substr(pos + 1));
    }
    return vec;
  }

  #if defined(_WIN32)
    enum MEMTYP {
      MEMCMD,
      MEMENV,
      MEMCWD
    };

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

    std::vector<wchar_t> cwd_cmd_env_from_proc(HANDLE proc, int type) {
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
      PVOID buf = nullptr; len = 0;
      if (type == MEMCWD) {
        buf = upp.CurrentDirectory.DosPath.Buffer;
        len = upp.CurrentDirectory.DosPath.Length;
      } else if (type == MEMENV) {
        buf = upp.Environment;
        len = (ULONG)upp.EnvironmentSize;
      } else if (type == MEMCMD) {
        buf = upp.CommandLine.Buffer;
        len = upp.CommandLine.Length;
      }
      buffer.resize(len / 2 + 1);
      ReadProcessMemory(proc, buf, &buffer[0], len, &nRead);
      if (!nRead) return buffer;
      buffer[len / 2] = L'\0';
      return buffer;
    }
  #endif

  #if (defined(__APPLE__) && defined(__MACH__))
    enum MEMTYP {
      MEMCMD,
      MEMENV
    };

    std::vector<std::string> cmd_env_from_proc_id(ngs::ps::NGS_PROCID proc_id, int type) {
      std::vector<std::string> vec;
      std::size_t len = 0;
      int argmax = 0, nargs = 0;
      char *procargs = nullptr, *sp = nullptr, *cp = nullptr;
      int mib[3];
      mib[0] = CTL_KERN;
      mib[1] = KERN_ARGMAX;
      len = sizeof(argmax);
      if (sysctl(mib, 2, &argmax, &len, nullptr, 0)) {
        std::cout << "Unaccessible or missing PID: " << proc_id << "\n";
        return vec;
      }
      procargs = (char *)malloc(argmax);
      if (!procargs) {
        std::cout << "Unaccessible or missing PID: " << proc_id << "\n";
        return vec;
      }
      mib[0] = CTL_KERN;
      mib[1] = KERN_PROCARGS2;
      mib[2] = proc_id;
      len = argmax;
      if (sysctl(mib, 3, procargs, &len, nullptr, 0)) {
        std::cout << "Unaccessible or missing PID: " << proc_id << "\n";
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
        if (type && i >= nargs) {
          vec.push_back(sp);
        } else if (!type && i < nargs) {
          vec.push_back(sp);
        }
        sp += strlen(sp) + 1;
        i++;
      }
      free(procargs);
      return vec;
    }

  #elif defined(__FreeBSD__)
    kinfo_file *kinfo_file_from_proc_id(ngs::ps::NGS_PROCID proc_id, int *cntp) {
      *cntp = 0;
      int cnt = 0;
      std::size_t len = 0;
      char *buf = nullptr, *bp = nullptr, *eb = nullptr;
      kinfo_file *kif = nullptr, *kp = nullptr, *kf = nullptr;
      int mib[4];
      mib[0] = CTL_KERN;
      mib[1] = KERN_PROC;
      mib[2] = KERN_PROC_FILEDESC;
      mib[3] = proc_id;
      if (sysctl(mib, 4, nullptr, &len, nullptr, 0)) {
        return nullptr;
      }
      len = len * 4 / 3;
      buf = (char *)malloc(len);
      if (!buf) {
        return nullptr;
      }
      if (sysctl(mib, 4, buf, &len, nullptr, 0)) {
        free(buf);
        return nullptr;
      }
      bp = buf;
      eb = buf + len;
      while (bp < eb) {
        kf = (kinfo_file *)(std::uintptr_t)bp;
        if (!kf->kf_structsize) break;
        bp += kf->kf_structsize;
        cnt++;
      }
      kif = (kinfo_file *)calloc(cnt, sizeof(*kif));
      if (!kif) {
        free(buf);
        return nullptr;
      }
      bp = buf;
      eb = buf + len;
      kp = kif;
      while (bp < eb) {
        kf = (kinfo_file *)(std::uintptr_t)bp;
        if (!kf->kf_structsize) break;
        memcpy(kp, kf, kf->kf_structsize);
        bp += kf->kf_structsize;
        kp->kf_structsize = sizeof(*kp);
        kp++;
      }
      free(buf);
      *cntp = cnt;
      return kif;
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

      std::vector<wchar_t> buffer = cwd_cmd_env_from_proc(proc, MEMENV);
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
      vec = cmd_env_from_proc_id(proc_id, MEMENV);

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

    struct is_invalid {
      bool operator()(const std::string &s) {
        return (s.find('=') == std::string::npos);
      }
    };
    vec.erase(std::remove_if(vec.begin(), vec.end(), is_invalid()), vec.end());
    return vec;
  }

  std::string envvar_value_from_proc_id(NGS_PROCID proc_id, std::string name) {
    std::string value;
    if (proc_id < 0 || name.empty()) return value;
    std::vector<std::string> vec = environ_from_proc_id(proc_id);
    if (!vec.empty()) {
      for (std::size_t i = 0; i < vec.size(); i++) {
        message_pump();
        std::vector<std::string> equalssplit = string_split_by_first_equals_sign(vec[i]);
        if (equalssplit.size() == 2) {
          #if defined(_WIN32)
            std::transform(equalssplit[0].begin(), equalssplit[0].end(), equalssplit[0].begin(), ::toupper);
            std::transform(name.begin(), name.end(), name.begin(), ::toupper);
          #endif
          if (equalssplit[0] == name) {
            value = equalssplit[1];
            break;
          }
        }
      }
    }
    return value;
  }

  bool envvar_exists_from_proc_id(NGS_PROCID proc_id, std::string name) {
    bool exists = false;
    if (proc_id < 0 || name.empty()) return exists;
    std::vector<std::string> vec = environ_from_proc_id(proc_id);
    if (!vec.empty()) {
      for (std::size_t i = 0; i < vec.size(); i++) {
        message_pump();
        std::vector<std::string> equalssplit = string_split_by_first_equals_sign(vec[i]);
        if (!equalssplit.empty()) {
          #if defined(_WIN32)
            std::transform(equalssplit[0].begin(), equalssplit[0].end(), equalssplit[0].begin(), ::toupper);
            std::transform(name.begin(), name.end(), name.begin(), ::toupper);
          #endif
          if (equalssplit[0] == name) {
            exists = true;
            break;
          }
        }
      }
    }
    return exists;
  }

  namespace {

    std::unordered_map<NGS_PROCID, std::intptr_t> stdipt_map;
    std::unordered_map<NGS_PROCID, std::string> stdopt_map;
    std::unordered_map<NGS_PROCID, bool> complete_map;
    std::unordered_map<int, NGS_PROCID> child_proc_id;
    std::unordered_map<int, bool> proc_did_execute;
    std::string standard_input;
    std::mutex stdopt_mutex;

  } // anonymous namespace

} // namespace ngs::ps
