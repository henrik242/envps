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

#pragma once
#include <vector>
#include <string>

namespace ngs::ps {

  #if !defined(_WIN32)
  typedef int NGS_PROCID;
  #else
  typedef unsigned long NGS_PROCID;
  #endif

  std::vector<std::string> environ_from_proc_id(NGS_PROCID proc_id);
  std::string envvar_value_from_proc_id(NGS_PROCID proc_id, std::string name);
  bool envvar_exists_from_proc_id(NGS_PROCID proc_id, std::string name);

} // namespace ngs::ps
