# memberref2yara
Dump .NET MemberRef Table as a Yara Rule.

This is rather unstable right now. You have been warned.

Quick and dirty tool to dump the MemberRef table from .NET PE Files and
also generate a Yara rule for the table data.

## Requirements
* python3 (Tested with python3.7)
* vivisect
* pefile

## Bugs
Yes, there are bugs. This is alpha software and a project for learning.
I will fix them. Real Soon Now™

## TODO
* Fix rule name
* Ditch all superfluous code
* Scan for .NET magic vs. offset from CLI header
* Swap pefile for vivisect PE library
* Add some additional helpers
* For the love of all that is holy, add some error handling!

