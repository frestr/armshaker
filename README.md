# armshaker
armshaker is processor fuzzer targeting the Armv8-A ISA. It can be used to find hidden instructions in hardware processors or other implementations of the ISA like emulators. 

In essence, it works by executing undefined instructions and checking whether the execution generates an undefined instruction exception or not, in the form of a SIGILL signal sent to the process. If no SIGILL is received, the instruction is marked as hidden and logged. The limited size of the three instruction sets in Armv8-A (A64, A32 and T32) makes it feasible to do an exhaustive search over the whole instruction space using this method.

## Usage

armshaker has two primary parts: the back-end doing most of the work, and a front-end adding visualizations and multiprocessing support. In most cases, the front-end is the preferred way to run the fuzzer.

The fuzzer must be compiled the first time, which can usually be done with a simple

```
make
```

The particular instruction set that is fuzzed depends on the runtime of the current system. If the fuzzer is compiled with a 32-bit (AArch32) toolchain, it will be able to fuzz A32 or T32 (with the `-t` option). If it is compiled with a 64-bit toolchain (AArch64), it will be able to fuzz A64, although cross-compiling and running a 32-bit application from AArch64 is possible.

Then an exhaustive search of the instruction set the fuzzer was compiled with can be initiated like so:

```
./armshaker.py -f3
```

The front-end will show the current status of the fuzzing session, with both a summary and the details for each worker. If a hidden instruction is found, it will be logged in the file `data/logX`, where `X` corresponds to the worker ID. Each log entry will be in the following format: `<instruction_encoding>,hidden,<generated_signal_number>,<register_values_before-after>...`.

## Building

armshaker is only supported on Armv8-A-based systems running Linux, but otherwise requires only a C compiler and Python for the front-end.

The simplest way to compile the fuzzer is to run

```
make
```

in the project directory. This will use the bundled libopcodes disassembler and should work for most use cases.

Optionally, a local installation of libopcodes can be used instead with

```
make SHARED_LIBOPCODES=TRUE
```

Capstone can also be used in addition to libopcodes (note: not instead of). This is mostly a legacy feature, but can be used to compare disassembly results between the two. It can be enabled by adding the `USE_CAPSTONE=TRUE` option when compiling.

In case Python 3 is not available, `shell_frontend.sh` can be used instead for multiprocessing support. Otherwise the fuzzer back-end can be run directly with `./fuzzer <options>`.

## Options

Listing of options available

## References

armshaker was inspired by Christopher Domas's [sandsifter](https://github.com/xoreaxeaxeax/sandsifter) project, and implemented as a part of my master's thesis in computer science where I used armshaker to fuzz a variety of Armv8-A-based systems. No hidden instructions that could be attributed to hardware were found, but the fuzzing did reveal bugs in the QEMU emulator and the Linux kernel. See the `refs` directory for more information.
