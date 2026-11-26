# Security

Report a problem by opening an issue at https://github.com/FileSherlock/k15/issues.

## Credits

- [dstroy0](https://github.com/dstroy0): audit of `src/`, 20 findings with fixes
  ([issue 1](https://github.com/FileSherlock/k15/issues/1)). Fixes in c4d4032 and a2d8893; the rest are answered in the issue.
- Reddit user [datkenny](https://www.reddit.com/user/datkenny/): review aimed at the
  private key ([report](https://pastebin.com/izRBKd02)). Found no key disclosure; noted
  that `oohold` relies on `drain`'s frame limit to bound its copy.
- [Patrick O'Reilly](https://github.com/ohohoreilly): further review aimed at the
  private key.
- [Boltthecat19](https://github.com/Boltthecat19): review aimed at the private key
  ([issue 2](https://github.com/FileSherlock/k15/issues/2)). Found no key disclosure;
  noted that a response index past the table would send memory beyond it (nothing
  stores one).
- And also thank you to everyone else that had a try on getting the key out!
