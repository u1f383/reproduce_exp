- title: ptrace getfd (No CVE for this bug wich has never been in the official kernel)
- description:
    - https://lkml.org/lkml/2019/12/5/814
    - a commit leads the file object UAF. I apply the similar patch into latest kernel version and try to exploit it for practice.
- PoC:
    - cross cache, make user_key_payload occupy the UAF object
    - CEA (cpu_entry_area) is randomized in linux 6.4-rc3, and I have no idea how to close file object again (file->f_op->flush != NULL)
