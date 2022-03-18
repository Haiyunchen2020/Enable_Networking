#define _GNU_SOURCE
#include <signal.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


struct _arg_t {
	int argc;
	char **argv;
};

const char *HOSTNAME = "debian";

void run(int argc, char *args[]);
int runContainerAsChild(struct _arg_t *arg);
int runSetupContainer(void *arg);
void setupContainer();

void setupHostVirtNet(pid_t pid);   //done in the host
void setupContainerVirtNet();  //done in the container


void setupContainerCGroup();
void setupContainerMemoryController();

void undoContainer();


/*
void help_and_exit(char *progname) {
//        printf ("Usage: %s run image application\n",progname);
        printf ("Usage: %s run image\n",progname);
        exit (EXIT_FAILURE);
}
*/

void help_and_exit() {
	printf ("Usage: bcdocker run image\n");
	exit (EXIT_FAILURE);
}


void fail_and_exit(char *msg) {
	perror(msg);
	exit (EXIT_FAILURE);
}





const int STACK_SIZE = 1024*1024;
const int BUF_SIZE = 1024;

//const char *BC_CONTAINER_HOSTNAME = "bcdocker";
//const char *BC_CONTAINER_HOSTNAME = "docker_container";


int main (int argc, char *argv[]) {
	char *prog, *cmd, **args;

	if (argc < 3) {
		help_and_exit();
	}

	prog = argv[0];
	cmd = argv[1];
	argc -= 2;
	args = argv+2;

	if (strcmp(cmd, "run") == 0) {
		run (argc, args);
	}
	else {
		help_and_exit();
	}

	exit(EXIT_SUCCESS);

}



void run(int argc, char *argv[]) {
	pid_t pid;
	struct _arg_t arg = {
		.argc = argc,
		.argv = argv
	};
	char *stack, *stackTop;

	stack = malloc(STACK_SIZE);
	stackTop = stack + STACK_SIZE;

	pid = clone (runSetupContainer, stackTop, CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | SIGCHLD, &arg);
	if (pid == -1) {
		perror("Cannot clone()");
		exit(EXIT_FAILURE);
	}

	setupHostVirtNet(pid);
	if (waitpid(pid, NULL, 0) == -1) {
		perror("Cannot waitpid(pid ...)");
		exit(EXIT_FAILURE);
	}
}



int run_setup_container(void *arg) {
	struct _arg_t *argpt = (struct _arg_t *)arg;
	char *root = argpt->argv[0];
	argpt->argc --;
	argpt->argv = argpt->argv +1;

	sleep(2);
	for (int i=0; i<argpt->argc; i++) {
		printf("%s\n, argpt->argv[i]");
	}

	setupContainer(root);
	runContainerAsChild(argpt);

}




/*
int run_setup_container(void *arg) {
        char hostname [BUF_SIZE];
        char **argv = (char **)arg;

        printf("child pid = %d\n", getpid());
        //gethostname(hostname,BUF_SIZE);
        //printf("hostname = %s\n", hostname);
//        sethostname(BC_CONTAINER_HOSTNAME, strlen(BC_CONTAINER_HOSTNAME));
        sethostname(HOSTNAME, strlen(HOSTNAME));
        gethostname(hostname,BUF_SIZE);
        printf("hostname = %s\n", hostname);

        if (chroot(argv[2]) == -1) {
                     fail_and_exit("cannot chroot(container_root..)");
             }
        
        //if (chroot("/home/brooklyn/pro2/cisc7310sys") == -1) {
        //        fail_and_exit("choot(/home/brooklyn/pro2/cisc7310sys)");
        //}
        //system("ls -l /");
        //system("ls -l");
        chdir("/");
        //system("ls -l .");

        if (mount("proc", "proc", "proc", 0, NULL) == -1) {
                fail_and_exit ("mount(proc ...)");
        }

        //run_app("/usr/bin/dash");
        run_app(argv[3]);
}
*/




void setupContainer(char * root) {
	if (sethostname(HOSTNAME, strlen(HOSTNAME)) == -1) {
		perror("Cannot sethostname()");
		exit(EXIT_FAILURE);
	}
	setupContainerVirtNet();
	setupContainerCGroup();
	setupContainerMemoryController();
	chroot(root);
	chdir("/");
	if (mount("proc", "proc", "proc", 0, "") == -1) {
		perror("Cannot mount(proc)");
		exit(EXIT_FAILURE);
	}
}





int runContainerAsChild(struct _arg_t *arg) {
	pid_t pid, sid;
	char **argv;

	printf("runContanerAsChild() ... \n");

	argv = malloc ((1+arg->argc)*sizeof(char *));
	if (argv == NULL) {
		perror("Cannot malloc");
		exit(EXIT_FAILURE);
	}
	for (int i=0; i<arg->argc; i++) {
		argv[i] = arg->argv[i];
	}
	argv[arg->argc] = NULL;

	pid = fork();
	if (pid == 0) {    //child
		printf("starting %s\n", argv[0]);
		if (execvp(argv[0], argv) == -1) {
			perror("Cannot execvp()");
			exit(EXIT_FAILURE);
		}
	}
	else  if (pid == -1) {   //error
		perror("Cannot fork()");
		exit(EXIT_FAILURE);
	}
	else {       //parent
		waitpid(pid, NULL, 0);
		undoContainer();
		free(argv);
	}
}





void setupHostVirtNet(pid_t pid) {
	char buf[1024];

	/* add virtual Ethernet devices, which must always be in pair */
	//Note below: bcvirt0 is network in host's end, bcvirt1 is network in container's end.
	sprintf(buf, "ip link add name bcvirt0 type veth peer name bcvirt1 netns %d", pid);
	system(buf);

	/*bring up the Ethernet interface */
	system("ip link set bcvirt0 up");

	/* add an IPv4 address to the Ethernet device */
	system("ip address add 192.168.57.1/24 dev bcvirt0");

	/* set up NAT (NAPT) */
	system("iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE");
	system("iptables -A FORWARD -i enp0s3 -o bcvirt0 -m state --state RELATED, ESTABLISHED -j ACCEPT");
	system("iptables -A FORWARD -i bcvirt0 -o enp0s3 -j ACCEPT");

}



void setupContainerVirtNet() {
	system("ip link set lo up");
	system("ip link set bcvirt1 up");
	system("ip address add 192.168.57.2/24 dev bcvirt1");
	system("ip route add 192.168.57.2/24 via 192.168.57.1");
	system("ip route add default via 192.168.57.1");
}



void setupContainerCGroup() {
	const char *DIRS[] = {"/sys", "/sys/fs", "/sys/fs/cgroup", "/sys/fs/cgroup/pids", "/sys/fs/cgroup/pids/debian"};
	const char *PN_CONTROLLER = "/sys/fs/cgroup/pids";
	char path [PATH_MAX];
	const int BUF_SIZE = 128;
	char buf[BUF_SIZE];
	int fd;
	struct stat sb;

	for (int i=0; i<sizeof(DIRS)/sizeof(char*); i++) {
		mkdir(DIRS[i], 0755);
		if (stat(DIRS[i], &sb) != 0 || !S_ISDIR(sb.st_mode)) {
			fprintf(stderr, "Cannot create %s\n", DIRS[i]);
			exit(EXIT_FAILURE);
		}
	}

	snprintf(path, PATH_MAX, "%s/%s", PN_CONTROLLER, "debian/pids.max");
	printf("path = %s\n", path);
	fd = open(path, O_CREAT | O_WRONLY, 0700);
	if (fd == -1) {
		perror("Cannot open(path");
		exit(EXIT_FAILURE);
	}
	if (write(fd, "4", 1) == -1) {
		perror ("Cannot write(pid.max)");
		exit(EXIT_FAILURE);
	}
	close(fd);

	snprintf(path, PATH_MAX, "%s/%s", PN_CONTROLLER, "debian/notify_on_release");
	fd = open (path, O_CREAT | O_WRONLY | O_TRUNC, 0700);
	if (fd == -1) {
		perror("Cannot open(path)");
		exit(EXIT_FAILURE);
	}
	write(fd, "1", 1);
	close(fd);

	snprintf(path, PATH_MAX, "%s/%s", PN_CONTROLLER, "debian/cgroup.procs");
	fd = open (path, O_CREAT | O_WRONLY | O_TRUNC, 0700);
	if (fd == -1) {
		perror ("Cannot open(path)");
		exit(EXIT_FAILURE);
	}
	snprintf(buf, 128, "%d", getpid());
	printf("pid in buf = %s\n", buf);
	write(fd, buf, strlen(buf));
	close(fd);
}





void setupContainerMemoryController() {
	const char *DIRS[] = {"/sys", "/sys/fs", "/sys/fs/cgroup", "/sys/fs/cgroup/memory", "/sys/fs/cgroup/memory/debian"};
	const char *MEM_CONTROLLER = "/sys/fs/cgroup/memory/debian";
	const char *MEM_LIMIT_FILE = "/sys/fs/cgroup/memory/debian/memory.limit_in_bytes";
	const char *MEM_CONTROLLER_TASKS = "/sys/fs/cgroup/memory/debian/tasks";
	struct stat sb;
	int fd;
	const int BUF_SIZE = 128;
	char buf[BUF_SIZE];

	for (int i=0; i<sizeof(DIRS)/sizeof(char*); i++) {
		mkdir(DIRS[i], 0755);
		if (stat(DIRS[i], &sb) != 0 || !S_ISDIR(sb.st_mode)) {
			fprintf(stderr, "Cannot create %s\n", DIRS[i]);
			exit(EXIT_FAILURE);
		}
	}

	fd = open(MEM_LIMIT_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0700);
	if (fd == -1) {
		perror ("Cannot open(MEM_LIMIT_FILE ...");
		exit(EXIT_FAILURE);
	}
	write(fd, "32M", 3);
	close(fd);

	fd = open(MEM_CONTROLLER_TASKS, O_CREAT | O_WRONLY | O_TRUNC, 0700);
	if (fd == -1) {
		perror("Cannot open(MEM_CONTROLLER_TASKS ...");
		exit(EXIT_FAILURE);
	}
	snprintf(buf, 128, "%d", getpid());
	write(fd, buf, strlen(buf));
	close(fd);
}






void undoContainer() {
	if (umount("proc") == -1) {
		perror("Cannot umount(proc ...)");
	}
}






void run_container(int argc, char *argv[]) {
	pid_t pid;
	char *stack, *stackTop;

	stack = malloc(STACK_SIZE);
	if (stack == NULL) {
		fail_and_exit("Cannot malloc(STACK_SIZE)");
	}

	stackTop = stack + STACK_SIZE;


	//pid = clone(run_setup_container,stackTop,
                //CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | SIGCHLD, (void *)argv);
	pid = clone(run_setup_container,stackTop,
                CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWCGROUP | SIGCHLD, (void *)argv);

	if (pid == -1) {
		fail_and_exit("Cannot clone(run_setup_container ...)");
	}

	if (waitpid(pid, NULL, 0) == -1) {
		fail_and_exit("Cannot waitpid(pid, NULL, NULL)");
	}
}




int runSetupContainer(void *arg) {
	struct _arg_t *argpt = (struct _arg_t *)arg;
	char *root = argpt-> argv[0];
	argpt->argc --;
	argpt->argv = argpt->argv + 1;

	sleep(2);
	for (int i=0; i<argpt->argc; i++) {
		printf("%s\n argpt->argv[i]");
	}

	setupContainer(root);
	runContainerAsChild(argpt);
}






/*
void run_app(char *app) {
        char *argv[]={app,NULL};
        char *envp[]={"PATH=/bin:/usr/bin",NULL};
        pid_t pid;

        pid = fork();

        if (pid ==0) {           //child
                if (execve(app, argv, envp)== -1) {
                        fail_and_exit("execve(app ...)");
                }
        }
        else if (pid > 0) {         //parent
                if (waitpid(pid, NULL, 0) == -1) {
                        fail_and_exit("waitpid(child, ...)");
                }
        }
        else {                   //failure
                fail_and_exit("fork()");
        }

}
*/





