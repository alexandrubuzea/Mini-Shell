// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ 0
#define WRITE 1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* Execute cd. */

	char *final_path = NULL;

	if (dir == NULL)
		final_path = getenv("HOME");
	else
		final_path = get_word(dir);

	int result = chdir(final_path); /* change the directory */

	if (dir != NULL)
		free(final_path);

	if (result)
		return false;

	return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* Execute exit/quit. */
	return SHELL_EXIT; /* Replace with actual exit code. */
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* Sanity checks. */

	if (s == NULL)
		return -1;

	/* If builtin command, execute the command. */

	char *verb = get_word(s->verb);

	if (strcmp(verb, "cd") == 0) {
		free(verb);

		/* check for each redirect possibility*/

		if (s->out) {
			char *out = get_word(s->out);
			int fd = open(out, O_WRONLY | O_TRUNC | O_CREAT, 0644);

			free(out);
			close(fd);
		}

		if (s->err) {
			char *err = get_word(s->err);
			int fd = open(err, O_WRONLY | O_TRUNC | O_CREAT, 0644);

			free(err);
			close(fd);
		}

		bool res = shell_cd(s->params);

		if (res == true)
			return 0;

		return -1;
	} else if (strcmp(verb, "exit") == 0 || strcmp(verb, "quit") == 0) {
		int res = shell_exit();

		free(verb);

		return res;
	}

	/* If variable assignment, execute the assignment and return
	 * the exit status.
	 */

	if (strchr(verb, '=')) {
		const char *env_name = s->verb->string;
		char *env_value = get_word(s->verb->next_part->next_part);

		int res = setenv((const char *)env_name, (const char *)env_value, 1);

		free(env_value);
		free(verb);

		return res;
	}

	/* If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */

	pid_t child_pid = fork();

	if (child_pid < 0) {
		free(verb);
		return -1;
	} else if (child_pid > 0) {
		int status;

		int res = waitpid(child_pid, &status, 0);

		DIE(!res, "Error in child\n");

		free(verb);

		if (WIFEXITED(status))
			return WEXITSTATUS(status);

		return 0;
	}

	int size;

	char **argv = get_argv(s, &size);

	/* check for each redirect possibility */
	if (s->in != NULL) {
		char *in = get_word(s->in);
		int fd = open(in, O_RDONLY);

		if (fd < 0) {
			free(in);
			free(verb);
			exit(-1);
		}

		dup2(fd, STDIN_FILENO);
		close(fd);
		free(in);
	}

	/* if we have redirect at STDOUT and STDERR simultaneously */
	if (s->out != NULL && s->err != NULL) {
		char *out = get_word(s->out);
		char *err = get_word(s->err);

		/* if we have the same output file, open only once */
		if (!strcmp(out, err)) {
			int fd;

			if (s->io_flags & IO_OUT_APPEND)
				fd = open(out, O_WRONLY | O_APPEND | O_CREAT, 0644);
			else
				fd = open(out, O_WRONLY | O_TRUNC | O_CREAT, 0644);

			if (fd < 0) {
				free(out);
				free(err);
				free(verb);
				exit(-1);
			}

			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);
			free(out);
			free(err);
		} else { /* else open each file separately */
			int fd;

			if (s->io_flags & IO_OUT_APPEND)
				fd = open(out, O_WRONLY | O_APPEND | O_CREAT, 0644);
			else
				fd = open(out, O_WRONLY | O_TRUNC | O_CREAT, 0644);

			if (fd < 0) {
				free(out);
				free(verb);
				exit(-1);
			}

			dup2(fd, STDOUT_FILENO);
			close(fd);
			free(out);

			if (s->io_flags & IO_ERR_APPEND)
				fd = open(err, O_WRONLY | O_APPEND | O_CREAT, 0644);
			else
				fd = open(err, O_WRONLY | O_TRUNC | O_CREAT, 0644);

			if (fd < 0) {
				free(err);
				free(verb);
				exit(-1);
			}

			dup2(fd, STDERR_FILENO);
			close(fd);
			free(err);
		}
	} else { /* we can have redirect only to STDOUT or STDERR (not both) */
		if (s->out != NULL) {
			char *out = get_word(s->out);

			int fd;

			if (s->io_flags & IO_OUT_APPEND)
				fd = open(out, O_WRONLY | O_APPEND | O_CREAT, 0644);
			else
				fd = open(out, O_WRONLY | O_TRUNC | O_CREAT, 0644);

			if (fd < 0) {
				free(out);
				free(verb);
				exit(-1);
			}

			dup2(fd, STDOUT_FILENO);
			close(fd);
			free(out);
		}

		if (s->err != NULL) {
			char *err = get_word(s->err);

			int fd;

			if (s->io_flags & IO_ERR_APPEND)
				fd = open(err, O_WRONLY | O_APPEND | O_CREAT, 0644);
			else
				fd = open(err, O_WRONLY | O_TRUNC | O_CREAT, 0644);

			if (fd < 0) {
				free(err);
				free(verb);
				exit(-1);
			}

			dup2(fd, STDERR_FILENO);
			close(fd);
			free(err);
		}
	}

	/* launch new process */
	int res = execvp(verb, argv);

	if (res) {
		fprintf(stderr, "Execution failed for '%s'\n", verb);
		free(verb);
		exit(-1);
	}

	free(verb);

	for (size_t i = 0; i < (size_t)size; ++i)
		free(argv[i]);
	free(argv);

	exit(0);
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
							command_t *father)
{
	/* Execute cmd1 and cmd2 simultaneously. */

	pid_t pid = fork();

	if (pid < 0) {
		return -1;
	} else if (pid == 0) {
		/* run first command */
		int res = parse_command(cmd1, level + 1, cmd1->up);

		exit(res);
	}

	parse_command(cmd2, level + 1, father);

	int status;

	waitpid(pid, &status, 0); /* wait for the command to finish */

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	return true; /* Replace with actual exit status. */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
						command_t *father)
{
	/* Redirect the output of cmd1 to the input of cmd2. */

	int fd[2];

	int res = pipe(fd); /* create a pipe*/

	if (res)
		return false;

	pid_t pid1 = fork(); /* create a process for the first command */

	if (pid1 < 0) {
		return -1;
	} else if (pid1 == 0) { /* if in child process */
		close(fd[0]);

		dup2(fd[1], STDOUT_FILENO);

		int res = parse_command(cmd1, level + 1, cmd1->up);

		close(fd[1]);

		exit(res);
	}

	pid_t pid2 = fork(); /* create another process for the second command */

	if (pid2 < 0) {
		return -1;
	} else if (pid2 == 0) {
		close(fd[1]);

		dup2(fd[0], STDIN_FILENO);

		int res = parse_command(cmd2, level + 1, cmd2->up);

		close(fd[0]);
		exit(res);
	}

	close(fd[0]);
	close(fd[1]);

	int status;

	res = waitpid(pid2, &status, 0);

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	return (res != 0 ? true : false); /* Replace with actual exit status. */
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* sanity checks */

	if (c->op == OP_NONE) {
		/* Execute a simple command. */
		int res = parse_simple(c->scmd, level + 1, c);

		return res; /* Replace with actual exit code of command. */
	}

	int res;

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* Execute the commands one after the other. */
		parse_command(c->cmd1, level + 1, c);
		res = parse_command(c->cmd2, level + 1, c);
		return res;

	case OP_PARALLEL:
		/* Execute the commands simultaneously. */
		res = (int)run_in_parallel(c->cmd1, c->cmd2, level + 1, c);

		return 0;

	case OP_CONDITIONAL_NZERO:
		/* Execute the second command only if the first one
		 * returns non zero.
		 */
		res = parse_command(c->cmd1, level + 1, c);

		if (res)
			res = parse_command(c->cmd2, level + 1, c);

		return res;

	case OP_CONDITIONAL_ZERO:
		/* Execute the second command only if the first one
		 * returns zero.
		 */

		res = parse_command(c->cmd1, level + 1, c);

		if (!res)
			res = parse_command(c->cmd2, level + 1, c);

		return res;

	case OP_PIPE:
		/* Redirect the output of the first command to the
		 * input of the second.
		 */
		res = (int)run_on_pipe(c->cmd1, c->cmd2, level + 1, c);

		return res;

	default:
		return SHELL_EXIT;
	}

	return 0; /* Replace with actual exit code of command. */
}
