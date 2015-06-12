/*
 * This file is distributed as part of MaxScale by MariaDB Corporation.  It is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation,
 * version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright MariaDB Corporation Ab 2014
 */

/**
 * @file qlafilter.c - Quary Log All Filter
 * @verbatim
 *
 * QLA Filter - Query Log All. A primitive query logging filter, simply
 * used to verify the filter mechanism for downstream filters. All queries
 * that are passed through the filter will be written to file.
 *
 * The filter makes no attempt to deal with query packets that do not fit
 * in a single GWBUF.
 *
 * A single option may be passed to the filter, this is the name of the
 * file to which the queries are logged. A serial number is appended to this
 * name in order that each session logs to a different file.
 *
 * Date		Who		Description
 * 03/06/2014	Mark Riddoch	Initial implementation
 * 11/06/2014	Mark Riddoch	Addition of source and match parameters
 * 19/06/2014	Mark Riddoch	Addition of user parameter
 *
 * @endverbatim
 */
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <filter.h>
#include <modinfo.h>
#include <modutil.h>
#include <query_classifier.h>
#include <skygw_debug.h>
#include <skygw_utils.h>
#include <log_manager.h>
#include <time.h>
#include <sys/time.h>
#include <regex.h>
#include <string.h>

/** Defined in log_manager.cc */
extern int            lm_enabled_logfiles_bitmask;
extern size_t         log_ses_count[];
extern __thread log_info_t tls_log_info;

MODULE_INFO 	info = {
	MODULE_API_FILTER,
	MODULE_GA,
	FILTER_VERSION,
	"A simple query logging filter"
};

static char *version_str = "V1.1.1";

/*
 * The filter entry points
 */
static	FILTER	*createInstance(char **options, FILTER_PARAMETER **);
static	void	*newSession(FILTER *instance, SESSION *session);
static	void 	closeSession(FILTER *instance, void *session);
static	void 	freeSession(FILTER *instance, void *session);
static	void	setDownstream(FILTER *instance, void *fsession, DOWNSTREAM *downstream);
static	int	routeQuery(FILTER *instance, void *fsession, GWBUF *queue);
static	void	diagnostic(FILTER *instance, void *fsession, DCB *dcb);


static FILTER_OBJECT MyObject = {
    createInstance,
    newSession,
    closeSession,
    freeSession,
    setDownstream,
    NULL,		// No Upstream requirement
    routeQuery,
    NULL,		// No client reply
    diagnostic,
};

enum LoggingBehaviour {
	LOGGING_PER_INSTANCE,
	LOGGING_PER_SESSION,
	LOGGING_PER_DATABASE
};

/**
 * A instance structure, the assumption is that the option passed
 * to the filter is simply a base for the filename to which the queries
 * are logged.
 *
 * To this base a session number is attached such that each session will
 * have a unique name.
 */
typedef struct {
	int	sessions;	/* The count of sessions */
	char	*filebase;	/* The filename base */
	char	*source;	/* The source of the client connection */
	char	*userName;	/* The user name to filter on */
	char	*match;		/* Optional text to match against */
	regex_t	re;		/* Compiled regex text */
	char	*nomatch;	/* Optional text to match against for exclusion */
	regex_t	nore;		/* Compiled regex nomatch text */
	FILE*   fp;             /* File pointer for shared log */
	int     logging;        /* Logging behaviour; per instance, session or database */
} QLA_INSTANCE;

/**
 * The session structure for this QLA filter.
 * This stores the downstream filter information, such that the	
 * filter is able to pass the query on to the next filter (or router)
 * in the chain.
 *
 * It also holds the file descriptor to which queries are written.
 */
typedef struct {
	DOWNSTREAM	down;
	char		*filename;
	FILE		*fp;
	int		active;
	int		id;       /* Session id */
} QLA_SESSION;

/**
 * Implementation of the mandatory version entry point
 *
 * @return version string of the module
 */
char *
version()
{
	return version_str;
}

/**
 * The module initialisation routine, called when the module
 * is first loaded.
 */
void
ModuleInit()
{
}

/**
 * The module entry point routine. It is this routine that
 * must populate the structure that is referred to as the
 * "module object", this is a structure with the set of
 * external entry points for this module.
 *
 * @return The module object
 */
FILTER_OBJECT *
GetModuleObject()
{
	return &MyObject;
}

/*
 * Helpers
 */

/**
 * Interprets the parameter value for the option 'logging'.
 *
 * @param value The parameter value.
 * @return One of LOGGING_PER_INSTANCE, LOGGING_PER_SESSION or LOGGING_PER_DATABASE.
 */
static int
interpretLoggingParam(const char *value)
{
	int logging = LOGGING_PER_SESSION;

	// TODO: This check is unnecessary if value cannot be null.
	// TODO: What is the value if an entry "x=" is encountered in the
	// TODO: configuration file?
	if (value)
	{
		if (strcmp(value, "per-instance") == 0)
		{
			logging = LOGGING_PER_INSTANCE;
		}
		else if (strcmp(value, "per-session") == 0)
		{
			logging = LOGGING_PER_SESSION;
		}
		else if (strcmp(value, "per-database") == 0)
		{
			logging = LOGGING_PER_DATABASE;
		}
		else
		{
			LOGIF(LE, (skygw_log_write_flush(
			       LOGFILE_ERROR,
			       "qlafilter: Invalid value '%s' specified "
			       "for parameter 'logging'. Defaulting "
			       "to 'per-session'.\n", value)));
		}
	}
	else
	{
		LOGIF(LE, (skygw_log_write_flush(
		       LOGFILE_ERROR,
		       "qlafilter: No value specified for parameter "
		       "'logging', defaulting to 'per-session'.\n")));
	}

	return logging;
}

/**
 * Frees an QLA_INSTANCE.
 *
 * @param instance The instance to be freed.
 *
 * NOTE: Does NOT run regfree on re and nore. At this point we do not know
 *       whether they are valid or not. Consider including that information.
 */
static void
freeInstance(QLA_INSTANCE *instance)
{
	if (instance)
	{
		free(instance->filebase);
		free(instance->source);
		free(instance->userName);
		free(instance->match);
		free(instance->nomatch);
		if (instance->fp) {
			if (fclose(instance->fp) != 0) {
				LOGIF(LE, (skygw_log_write_flush(
					LOGFILE_ERROR,
					"qlafilter: Closing file failed: %s\n", strerror(errno))));
			}
		}

		free(instance);
	}
}

/*
 */
void logInfo(FILE *fp, const char *sql)
{
	ss_dassert(fp);
	ss_dassert(sql);

	struct tm t;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &t);
	// TODO: Consider checking whether the writing succeeds and log if does not,
	// TODO: but ensure that repeated problems do not overwhelm the log.
	fprintf(fp,
		"%02d:%02d:%02d.%-3d %d/%02d/%d, ",
		t.tm_hour, t.tm_min, t.tm_sec, (int)(tv.tv_usec / 1000),
		t.tm_mday, t.tm_mon + 1, 1900 + t.tm_year);
	fprintf(fp, "%s\n", sql);
}

void logSessionInfo(FILE *fp, const QLA_SESSION *session, const char *sql)
{
	ss_dassert(fp);
	ss_dassert(session);
	ss_dassert(sql);

	fprintf(fp, "[%d]: ", session->id);
	logInfo(fp, sql);
}

void logDatabaseInfo(const char* path, const char *sql)
{
	ss_dassert(path);
	ss_dassert(sql);

	FILE *fp = fopen(path, "w+");

	if (fp) {
		// TODO: It might be useful to log the session id also in this case.
		// TODO: However, in that case we need to ensure that the file is
		// TODO: truncated when it is opened for the first time as the
		// TODO: session ids start from 0 after each startup.

		logInfo(fp, sql);

		fclose(fp);
	} else {
		// TODO: Log this just once, otherwise we may overwhelm the log-file.
		LOGIF(LE, (skygw_log_write_flush(
			LOGFILE_ERROR,
			"qlafilter: Could not open %s: %s.\n", path, strerror(errno))));
	}
}

void logDatabasesInfo(GWBUF *queue,
		      const QLA_INSTANCE *instance,
		      const QLA_SESSION *session,
		      const char *sql)
{
	ss_dassert(queue);
	ss_dassert(instance);
	ss_dassert(session);
	ss_dassert(sql);

	// TODO: According to Markus, in relation to skygw_get_database_names:
	// TODO: "This does not take in to notice the current database set with
	// TODO:  a 'USE database;' query. This means that the filter itself would
	// TODO:  have to track the active database."

	int size;
	char** names = skygw_get_database_names(queue, &size);

	if (names) {
		int i;

		ss_dassert(instance->filebase);
		int baseLength = strlen(instance->filebase);

		for (i = 0; i < size; ++i) {
			const char *name = names[i];

			int length = baseLength + 1 + strlen(name) + 1; // "." and trailing null.

			char* path = malloc(length);

			if (path) {
				// TODO: Does the database name need to be sanitized?
				strcpy(path, instance->filebase);
				strcat(path, ".");
				strcat(path, name);

				logDatabaseInfo(path, sql);
				free(path);
			} else {
				// TODO: Log just once, otherwise we may overwhelm the log-file.
				LOGIF(LE, (skygw_log_write_flush(
					LOGFILE_ERROR,
					"qlafilter: Could not allocated memory for filename.\n")));
			}
		}

		// TODO: Add skygw_free_database_names(char** names, int size);
		for (i = 0; i < size; ++i) {
			free(names[i]);
		}
		free(names);
	} else {
		LOGIF(LE, (skygw_log_write_flush(
			LOGFILE_ERROR,
			"qlafilter: Could not get database names.\n")));
	}
}

/*
 * The filter entry points - Implementation
 */

/**
 * Create an instance of the filter for a particular service
 * within MaxScale.
 * 
 * @param options	The options for this filter
 * @param params	The array of name/value pair parameters for the filter
 *
 * @return The instance data for this new instance
 */
static	FILTER	*
createInstance(char **options, FILTER_PARAMETER **params)
{
QLA_INSTANCE	*my_instance;
int		i;

	if ((my_instance = calloc(1, sizeof(QLA_INSTANCE))) != NULL)
	{
		if (options){
			my_instance->filebase = strdup(options[0]);
		}else{
			my_instance->filebase = strdup("qla");
		}
		my_instance->source = NULL;
		my_instance->userName = NULL;
		my_instance->match = NULL;
		my_instance->nomatch = NULL;
		my_instance->logging = LOGGING_PER_SESSION;
		if (params)
		{
			for (i = 0; params[i]; i++)
			{
				if (!strcmp(params[i]->name, "match"))
				{
					my_instance->match = strdup(params[i]->value);
				}
				else if (!strcmp(params[i]->name, "exclude"))
				{
					my_instance->nomatch = strdup(params[i]->value);
				}
				else if (!strcmp(params[i]->name, "source"))
					my_instance->source = strdup(params[i]->value);
				else if (!strcmp(params[i]->name, "user"))
					my_instance->userName = strdup(params[i]->value);
				else if (!strcmp(params[i]->name, "filebase"))
				{
					if (my_instance->filebase){
						free(my_instance->filebase);
						my_instance->filebase = NULL;
					}
					my_instance->filebase = strdup(params[i]->value);
				}
				else if (!strcmp(params[i]->name, "logging"))
				{
					my_instance->logging = interpretLoggingParam(params[i]->value);
				}
				else if (!filter_standard_parameter(params[i]->name))
				{
					LOGIF(LE, (skygw_log_write_flush(
						LOGFILE_ERROR,
						"qlafilter: Unexpected parameter '%s'.\n",
						params[i]->name)));
				}
			}
		}
		my_instance->sessions = 0;
		if (my_instance->logging == LOGGING_PER_INSTANCE)
		{
			my_instance->fp = fopen(my_instance->filebase, "w");

			if (!my_instance->fp) {
				LOGIF(LE, (skygw_log_write_flush(LOGFILE_ERROR,
				       "qlafilter: Could not create file '%s': ",
				       my_instance->filebase, strerror(errno))));

				freeInstance(my_instance);
				return NULL;
			}
		}
		if (my_instance->match &&
			regcomp(&my_instance->re, my_instance->match, REG_ICASE))
		{
			LOGIF(LE, (skygw_log_write_flush(LOGFILE_ERROR,
				"qlafilter: Invalid regular expression '%s'"
				" for the match parameter.\n",
					my_instance->match)));
			freeInstance(my_instance);
			return NULL;
		}
		if (my_instance->nomatch &&
			regcomp(&my_instance->nore, my_instance->nomatch,
								REG_ICASE))
		{
			LOGIF(LE, (skygw_log_write_flush(LOGFILE_ERROR,
				"qlafilter: Invalid regular expression '%s'"
				" for the nomatch paramter.\n",
					my_instance->nomatch)));
			if (my_instance->match)
				regfree(&my_instance->re);
			freeInstance(my_instance);
			return NULL;
		}
	}
	return (FILTER *)my_instance;
}

/**
 * Associate a new session with this instance of the filter.
 *
 * Create the file to log to and open it.
 *
 * @param instance	The filter instance data
 * @param session	The session itself
 * @return Session specific data for this session
 */
static	void	*
newSession(FILTER *instance, SESSION *session)
{
QLA_INSTANCE	*my_instance = (QLA_INSTANCE *)instance;
QLA_SESSION	*my_session;
char		*remote, *userName;

	if ((my_session = calloc(1, sizeof(QLA_SESSION))) != NULL)
	{
		if (my_instance->logging == LOGGING_PER_SESSION) {
			if ((my_session->filename =
			     (char *)malloc(strlen(my_instance->filebase) + 20))
							== NULL)
			{
				LOGIF(LE, (skygw_log_write(
					LOGFILE_ERROR,
					"Error : Memory allocation for qla filter "
					"file name failed due to %d, %s.",
					errno,
					strerror(errno))));
				free(my_session);
				return NULL;
			}
		}
		my_session->active = 1;
		my_session->id = my_instance->sessions;
		
		if (my_instance->source 
			&& (remote = session_get_remote(session)) != NULL)
		{
			if (strcmp(remote, my_instance->source))
				my_session->active = 0;
		}
		userName = session_getUser(session);
		
		if (my_instance->userName && 
			userName && 
			strcmp(userName,my_instance->userName))
		{
			my_session->active = 0;
		}

		if (my_session->active && (my_instance->logging == LOGGING_PER_SESSION))
		{
			sprintf(my_session->filename, "%s.%d",
				my_instance->filebase,
				my_session->id);

			my_session->fp = fopen(my_session->filename, "w");
			
			if (my_session->fp == NULL)
			{
				LOGIF(LE, (skygw_log_write(
					LOGFILE_ERROR,
					"Error : Opening output file for qla "
					"fileter failed due to %d, %s",
					errno,
					strerror(errno))));
				free(my_session->filename);
				free(my_session);
				my_session = NULL;
			}
		}
	}
	else
	{
		LOGIF(LE, (skygw_log_write(
			LOGFILE_ERROR,
			"Error : Memory allocation for qla filter failed due to "
			"%d, %s.",
			errno,
			strerror(errno))));
	}

	if (my_session) {
		my_instance->sessions++;
	}

	return my_session;
}

/**
 * Close a session with the filter, this is the mechanism
 * by which a filter may cleanup data structure etc.
 * In the case of the QLA filter we simple close the file descriptor.
 *
 * @param instance	The filter instance data
 * @param session	The session being closed
 */
static	void 	
closeSession(FILTER *instance, void *session)
{
QLA_INSTANCE	*my_instance = (QLA_INSTANCE *)instance;
QLA_SESSION	*my_session = (QLA_SESSION *)session;

	if (my_instance->logging == LOGGING_PER_INSTANCE)
	{
		if (fflush(my_instance->fp) != 0) {
			LOGIF(LE, (skygw_log_write(
				LOGFILE_ERROR,
				"Error : Flushing instance log file failed: %s\n",
				strerror(errno))));
		}
	}
	else if (my_session->fp)
	{
		if (fclose(my_session->fp) != 0) {
			LOGIF(LE, (skygw_log_write(
				LOGFILE_ERROR,
				"Error : Closing session log file failed: %s\n",
				strerror(errno))));
		}
	}
}

/**
 * Free the memory associated with the session
 *
 * @param instance	The filter instance
 * @param session	The filter session
 */
static void
freeSession(FILTER *instance, void *session)
{
QLA_SESSION	*my_session = (QLA_SESSION *)session;

	free(my_session->filename);
	free(session);
        return;
}

/**
 * Set the downstream filter or router to which queries will be
 * passed from this filter.
 *
 * @param instance	The filter instance data
 * @param session	The filter session 
 * @param downstream	The downstream filter or router.
 */
static void
setDownstream(FILTER *instance, void *session, DOWNSTREAM *downstream)
{
QLA_SESSION	*my_session = (QLA_SESSION *)session;

	my_session->down = *downstream;
}

/**
 * The routeQuery entry point. This is passed the query buffer
 * to which the filter should be applied. Once applied the
 * query should normally be passed to the downstream component
 * (filter or router) in the filter chain.
 *
 * @param instance	The filter instance data
 * @param session	The filter session
 * @param queue		The query data
 */
static	int	
routeQuery(FILTER *instance, void *session, GWBUF *queue)
{
QLA_INSTANCE	*my_instance = (QLA_INSTANCE *)instance;
QLA_SESSION	*my_session = (QLA_SESSION *)session;
char		*ptr;
int		length = 0;


	// TODO: Should we log if the session is /not/ active but the
	// TODO: logging mode is something else than per-session?
	if (my_session->active)
	{
		if (queue->next != NULL)
		{
			queue = gwbuf_make_contiguous(queue);
		}
		if ((ptr = modutil_get_SQL(queue)) != NULL)
		{
			if ((my_instance->match == NULL ||
				regexec(&my_instance->re, ptr, 0, NULL, 0) == 0) &&
				(my_instance->nomatch == NULL ||
					regexec(&my_instance->nore,ptr,0,NULL, 0) != 0))
			{
				switch (my_instance->logging) {
				case LOGGING_PER_SESSION:
					logInfo(my_session->fp, ptr);
					break;

				case LOGGING_PER_INSTANCE:
					logSessionInfo(my_instance->fp, my_session, ptr);
					break;

				case LOGGING_PER_DATABASE:
					logDatabasesInfo(queue, my_instance, my_session, ptr);
					break;

				default:
					ss_dassert(!true);
				}
			}
			free(ptr);
		}
	}
	/* Pass the query downstream */
	return my_session->down.routeQuery(my_session->down.instance,
			my_session->down.session, queue);
}

/**
 * Diagnostics routine
 *
 * If fsession is NULL then print diagnostics on the filter
 * instance as a whole, otherwise print diagnostics for the
 * particular session.
 *
 * @param	instance	The filter instance
 * @param	fsession	Filter session, may be NULL
 * @param	dcb		The DCB for diagnostic output
 */
static	void
diagnostic(FILTER *instance, void *fsession, DCB *dcb)
{
QLA_INSTANCE	*my_instance = (QLA_INSTANCE *)instance;
QLA_SESSION	*my_session = (QLA_SESSION *)fsession;

	switch (my_instance->logging) {
	case LOGGING_PER_INSTANCE:
		dcb_printf(dcb, "\t\tLogging to file			%s.\n",
			my_instance->filebase);
		break;

	case LOGGING_PER_SESSION:
		if (my_session)
		{
			dcb_printf(dcb, "\t\tLogging to file			%s.\n",
				   my_session->filename);
		}
		break;

	case LOGGING_PER_DATABASE:
		dcb_printf(dcb, "\t\tLogging to file			%s.(database-name)\n",
			my_instance->filebase);
		break;

	default:
		ss_dassert(!true);
	}

	if (my_instance->source)
		dcb_printf(dcb, "\t\tLimit logging to connections from 	%s\n",
				my_instance->source);
	if (my_instance->userName)
		dcb_printf(dcb, "\t\tLimit logging to user		%s\n",
				my_instance->userName);
	if (my_instance->match)
		dcb_printf(dcb, "\t\tInclude queries that match		%s\n",
				my_instance->match);
	if (my_instance->nomatch)
		dcb_printf(dcb, "\t\tExclude queries that match		%s\n",
				my_instance->nomatch);
}
