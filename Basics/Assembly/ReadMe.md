## CALM DOWN: IT’S JUST ASSEMBLY !

# x86 Assembly Guide Introduction

The x86 instruction set architecture is at the heart of CPUs that power our home computers and remote servers for over two decades. Being able to read and write code in low-level assembly language is a powerful skill to have. It enables you to write faster code, use machine features unavailable in C, and reverse-engineer compiled code.

Assembly language is one of the closest forms of communication that humans can engage in with a computer. With assembly, the programmer can precisely track the flow of data and execution in a program in a mostly human-readable form. Once a program has been compiled, it is difficult (and at times, nearly impossible) to reverse-engineer the code into its original form. As a result, if you wish to examine a program that is already compiled but would rather not stare at hexadecimal or binary, you will need to examine it in assembly language. 

The prerequisites to reading this tutorial are working with binary numbers, moderate experience programming in an imperative language (C/C++/Java/Python/etc.), and the concept of memory pointers (C/C++). You do not need to know how CPUs work internally or have prior exposure to assembly language.

## Is it the Same On Windows/DOS/Linux?

The answers to this question are yes and no. The basic x86 machine code is dependent only on the processor. The x86 versions of Windows and Linux are obviously built on the x86 machine code. There are a few differences between Linux and Windows programming in x86 Assembly:

1. On a Linux computer, the most popular assemblers are the GAS assembler, which uses the AT&T syntax for writing code, and the Netwide Assembler, also known as NASM, which uses a syntax similar to MASM.
2. On a Windows computer, the most popular assembler is MASM, which uses the Intel syntax but also, a lot of Windows users use NASM.
3. The available software interrupts, and their functions, are different on Windows and Linux.
4. The available code libraries are different on Windows and Linux.

Using the same assembler, the basic assembly code written on each Operating System is basically the same, except you interact with Windows differently than you interact with Linux.