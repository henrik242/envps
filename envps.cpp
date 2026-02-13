/*

 MIT License

 Copyright © 2021-2023 Samuel Venable

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

#include <iostream>
#include <exception>
#include "process.hpp"

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "Usage: envps <pid>" << "\n";
        return 1;
    }
    int proc_id;
    try {
        proc_id = std::stoi(argv[1]);
    } catch (std::exception &e) {
        std::cerr << "Illegal PID: " << argv[1] << "\n";
        return 1;
    }
    std::vector<std::string> env = ngs::ps::environ_from_proc_id(proc_id);
    for (const auto &entry : env) {
        std::cout << entry << "\n";
    }
    return 0;
}
