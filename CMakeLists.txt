cmake_minimum_required(VERSION 3.20)
project(tcp_probe CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

set(TP_SOURCES
  src/segment.cpp
  src/reassembly.cpp
  src/policy.cpp
  src/utun.cpp
  src/trace.cpp
  src/sysctl.cpp
  src/clock.cpp
  src/peer.cpp
)

add_library(tp STATIC ${TP_SOURCES})
target_include_directories(tp PUBLIC include)

# The same sources with assertions left in, for the tests to link against.
#
# Without this, -UNDEBUG on a test target only re-enables the asserts written in
# the test file itself; every assert inside the library the test is exercising
# stays compiled out by Release's -DNDEBUG. That is the vacuous-pass failure the
# comment below warns about, one level down and easy to miss -- verified by
# putting assert(false) in src/reassembly.cpp and watching ctest stay green.
add_library(tp_checked STATIC ${TP_SOURCES})
target_include_directories(tp_checked PUBLIC include)
target_compile_options(tp_checked PRIVATE -UNDEBUG)

# And again under the sanitisers, for the same reason one level further.
# ASan's heap checks are runtime interceptors and would have caught a heap
# overflow in an uninstrumented library anyway -- but the wire encoder writes
# into STACK buffers (`uint8_t pkt[4+1500]` in Utun::send, `optbuf[40]` in
# build()), and stack-buffer-overflow detection is compile-time instrumentation.
# Linking a sanitised test against an unsanitised library leaves exactly the
# buffers this suite exists to check uninstrumented.
add_library(tp_asan STATIC ${TP_SOURCES})
target_include_directories(tp_asan PUBLIC include)
target_compile_options(tp_asan PRIVATE -UNDEBUG -fsanitize=address,undefined -g -O1)

enable_testing()

# ---------------------------------------------------------------- unit tests
# These need no root and no utun. That is the point: the parts of this project
# that can be wrong in a silent, results-changing way -- sequence arithmetic,
# reassembly, the option encoder, the loss policy -- are exactly the parts that
# do not need privilege, so anyone who clones this can run ctest and see them
# pass without being asked to trust a sudo binary.
#
# Release sets -DNDEBUG, which turns every assert() into nothing and makes a
# test suite pass vacuously. -UNDEBUG per target is not optional.
foreach(t checksum segment reassembly policy)
  add_executable(test_${t} tests/test_${t}.cpp)
  target_link_libraries(test_${t} PRIVATE tp_checked)
  target_compile_options(test_${t} PRIVATE -UNDEBUG)
  add_test(NAME ${t} COMMAND test_${t})
endforeach()

# Sanitiser variants of the same suites. The wire encoder does pointer
# arithmetic into a fixed buffer from length fields that, in the parse
# direction, come off the network -- ASan is the difference between "the tests
# pass" and "the tests pass and nothing scribbled past the end of a buffer".
foreach(t segment reassembly)
  add_executable(test_${t}_asan tests/test_${t}.cpp)
  target_link_libraries(test_${t}_asan PRIVATE tp_asan)
  target_compile_options(test_${t}_asan PRIVATE -UNDEBUG -fsanitize=address,undefined -g -O1)
  target_link_options(test_${t}_asan PRIVATE -fsanitize=address,undefined)
  add_test(NAME ${t}_asan COMMAND test_${t}_asan)
endforeach()

# ---------------------------------------------------------------- experiments
# Everything here needs root, because creating a utun goes through
# PF_SYSTEM/SYSPROTO_CONTROL. They are NOT registered with ctest: a suite that
# fails for anyone who runs it without sudo trains people to ignore red.
foreach(e baseline hol dupack rto challenge_ack)
  add_executable(exp_${e} experiments/exp_${e}.cpp)
  target_link_libraries(exp_${e} PRIVATE tp)
endforeach()
