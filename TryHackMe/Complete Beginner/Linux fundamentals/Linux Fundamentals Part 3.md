#Linux 

### Downloading files:

`wget` - Downloading web files
`scp` (secure copy) - Transfer files from or to a remote system using ssh
`python3 -m http.server` - Serve files from a directory
updog - A more advanced yet lightweight webserver

### Processes:

PID - The number of the process by starting order
`ps` - Command for showing all running process
`top` - Gives a real time statistics about the processes running, refreshes every 10 seconds or when you move with your arrows
`kill` - Kill a process

signals you can send with `kill`:
SIGTERM - Do cleanup tasks beforehand
SIGKILL - Don't do any cleanup after the fact
SIGSTOP - Stop/suspend a process

namespaces - Used by the os to split resources between processes
Only processes in the same namespace can see each other

PID 0 process - The system's init on Ubuntu, such as systemed, sits between the os and the user and manages user processes
systemmd - One of the first processes to run, all programs and software pieces that we run are a child process of systemmd

`systemctl` - For enabling/disabling processes on startup or telling them to start/stop
`Ctrl + Z` - Another way of running process in the background
`fg` - Bring process back to the foreground

`crontabs` - Get started during boot, responsible for facilitating and managing cron jobs
cron process executes each line on the crontab file step by step

Crontab required values:
1. MIN - What minute to execute at
2. HOUR - What hour to execute at
3. DOM - What day of the month to execute at
4. MON - What month of the year to execute at
5. DOW - What day of the week to execute at
6. CMD - The actual command that will be executed

Example of backing up a folder each 12 hours:
`0 *12 * * * cp -R /home/cmnatic/documents /var/backups/`
`*` - When we don't want to add value

`crontab -e` - Edit crontab

`add-apt-repository` - add community repository
`dpkg` - package installer (not updated when we update our system)
GPG (Gnu Privacy Guard) keys - Guarantees the integrity of, checks that the system trusts the keys and that this is what the developers used

Adding sublime text editor repository:

1. Getting the key for sublime text 3 and using apt-key to trust it - `wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | sudo apt-key add -`
2. Now we need to add the repository to are apt sources list, it's a good practice to have a separate file for each community/third party repository we add
2.1. Creating a file named **sublime-text.list** in **/etc/apt/sources.list.d**
2.2. Adding and saving the repository to the newly created file
2.3. `apt update` - For recognising the new entry
2.4. `apt install sublime-text` - Installing the software

Removing packages:
1. `add-apt-repository --remove ppa:PPA_Name/ppa` or manually deleting the file created for the repository
2. `apt remove [software name]`

rotating - Process of automatically managing the logs by the operating system


