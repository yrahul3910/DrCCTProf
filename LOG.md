# Alias drrun

```
alias drrun="$PWD/build/bin64/drrun -t drcctlib_heap_overflow -- ./test_apps/build/test_app_heap.cpp"
alias testpath="./test_apps/build/test_app_cct"

drrun -t drcctlib_memory_only -- testpath/test_app_cct
drrun -t drcctlib_instr_statistics -- $PWD/test_apps/build/test_app_cct -debug
```
