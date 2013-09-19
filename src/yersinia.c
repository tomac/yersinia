/* yersinia.c
 * Command line client and application main entry point
 *
 * Yersinia
 * By David Barroso <tomac@yersinia.net> and Alfredo Andres <slay@yersinia.net>
 * Copyright 2005, 2006, 2007 Alfredo Andres and David Barroso
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef lint
static const char rcsid[] = 
"$Id: yersinia.c 43 2007-04-27 11:07:17Z slay $";
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _REENTRANT

#include <stdio.h>
#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include <sys/socket.h>       

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#else
#ifdef HAVE_NETINET_IN_SYSTEM_H
#include <netinet/in_system.h>
#endif
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_BSTRING_H
#include <bstring.h>
#endif

#ifdef STDC_HEADERS
#include <stdlib.h>
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#ifdef HAVE_GTK
#include <gtk/gtk.h>
#endif

#include <termios.h>

#include <stdarg.h>

#include "yersinia.h"

/*
 * Use global *tty_tmp and term_parent
 */
int
main( int argc, char **argv )
{
   struct cl_args *cl_args;
   struct term_node *tty_node = NULL;
   pid_t pid;
   pid_t parent_id;
#if defined(HAVE_PTHREAD_SETCONCURRENCY) && !defined(LINUX)
   int concurrent;
#endif

   handle_signals_parent();

   tcgetattr(0, &term_parent);   

   parent_id = getpid();

   if ((pid = fork()) < 0)
   {
      exit(1);
   }
   else
   {
      if (pid != 0)
      {
         wait(NULL);
         tcsetattr(0, TCSANOW, &term_parent);
         exit(0);
      }
   }

   fatal_error = 4;

   /* Disable all signals while initializing data...*/
   handle_signals();

   setvbuf(stdout, NULL, _IONBF, 0);

   tty_tmp = (struct term_tty *)calloc(1,sizeof(struct term_tty));

   if (tty_tmp == NULL)
   {
      printf("Out of memory on calloc tty_tmp\n");
      clean_exit();
   }

   tty_tmp->term = (struct termios *)calloc(1,sizeof(struct termios));      

   if (tty_tmp->term == NULL)
   {
      printf("Out of memory on calloc tty_tmp->term\n");
      clean_exit();
   }

   /* default values */
   tty_tmp->interactive = 0;
   tty_tmp->gtk = 0;
   tty_tmp->attack = -1;
   tty_tmp->mac_spoofing = -1;
   tty_tmp->splash = -1;
   strncpy(tty_tmp->username, VTY_USER, MAX_USERNAME);
   strncpy(tty_tmp->password, VTY_PASS, MAX_PASSWORD);
   strncpy(tty_tmp->e_password, VTY_ENABLE, MAX_PASSWORD);
   tty_tmp->port = VTY_PORT;
   tty_tmp->ip_filter = NULL;
#ifdef HAVE_GTK
   tty_tmp->buffer_log = NULL;
#endif

   cl_args = (struct cl_args *)calloc(1,sizeof(struct cl_args));

   if (cl_args == NULL)
   {
      printf("Out of memory on calloc cl_args\n");
      clean_exit();
   }

   if ( argc == 1 )                                                          
   {
      printf("GNU %s %s\n", PACKAGE, VERSION);
      printf("Try '%s -h' to display the help.\n",PACKAGE);
      clean_exit();
   }

   if (getuid() != 0) 
   {
      printf("You must be root to run %s %s\n", PACKAGE, VERSION);
      clean_exit();
   }

   if (term_init() < 0)
      g00dbye();

   /* Register all the protocols */
   protocol_init();

   cl_args->proto_index = -1;

   if (parser_initial(tty_tmp, cl_args, argc, argv) < 0) {
      clean_exit();
   } 

   init_log();

#if defined(HAVE_PTHREAD_SETCONCURRENCY) && !defined(LINUX)
/*   concurrent = pthread_getconcurrency();*/

   concurrent = 15;/*(MAX_TERMS*MAX_PROTOCOLS*MAX_THREAD_ATTACK*2)+3;*/

   if (pthread_setconcurrency(concurrent) != 0)
   {
      thread_error("init pthread_setconcurrency()",errno);
      g00dbye();
   }
#endif

   if (interfaces_init(&terms->pcap_listen_th) < 0 )
      g00dbye();

   /* Establish TERM signal handler...*/
   posix_signal(SIGTERM, final);


#ifdef HAVE_REMOTE_ADMIN
   if (tty_tmp->daemonize)
   {
      if (admin_init(tty_tmp) < 0)
         g00dbye();
   }
#endif 

   if (thread_create(&terms->uptime_th.id, &th_uptime, (void *)NULL) < 0)
      g00dbye();

   /* Command line and ncurses cannot be choosed simultaneously...*/
   if ((!tty_tmp->interactive) && (!tty_tmp->gtk) && (cl_args->proto_index != -1)) 
   {
      terms->work_state = INITIAL;
      tty_node = term_type[TERM_TTY].list;
      if (thread_create(&tty_node[0].thread.id, &th_tty_peer, 
               (void *)cl_args) < 0)
         g00dbye();

      while(terms->work_state != STOPPED)
         thread_usleep(100000);
   }

#ifdef HAS_CURSES
   if (tty_tmp->interactive)
   {
      terms->work_state = INITIAL;
      if (thread_create(&terms->gui_th.id, &ncurses_gui, NULL) < 0 )
         g00dbye();
      /* Wait until the ncurses GUI is over */
      while(terms->work_state != STOPPED)
         thread_usleep(100000);
   }
   else
   {
#endif
#ifdef HAVE_GTK
      if (tty_tmp->gtk)
      {
         terms->work_state = INITIAL;
         if (thread_create(&terms->gui_gtk_th.id, &gtk_gui, NULL) < 0 )
            g00dbye();
         /* Wait until the GTK GUI is over */
         while(terms->work_state != STOPPED)
            thread_usleep(100000);
      }
#endif
#ifdef HAS_CURSES
   }
#endif

#ifdef HAVE_REMOTE_ADMIN
   if (tty_tmp->daemonize)
   {
      /* Ok, now that console (ncurses) is finished
       * we can become a true daemon... */
      become_daemon(parent_id);

      /* Wait until some important thread exits due to fatal_error...*/
      while (fatal_error == 4)
         thread_usleep(100000);
   }
#endif

   g00dbye();

   exit(1);
}


/*
 * Thread for handling command line attacks (TERM_TTY)
 * Use global variable struct term_tty *tty_tmp
 */
void *
th_tty_peer(void *args)
{
   int fail;
   time_t this_time;
   struct cl_args *arguments;
   struct term_tty *tty;
   struct term_node *term_node=NULL;
   sigset_t mask;
   
   terms->work_state = RUNNING;
   
write_log(0, "\n th_tty_peer thread = %d...\n",(int)pthread_self());
   
   sigfillset(&mask);
   
   if (pthread_sigmask(SIG_BLOCK, &mask,NULL))
   {
      thread_error("th_tty_peer pthread_sigmask()",errno);
      th_tty_peer_exit(NULL);
   }   

   if (pthread_mutex_lock(&terms->mutex) != 0)
   {
      thread_error("th_tty_peer pthread_mutex_lock",errno);
      th_tty_peer_exit(NULL);
   }
   
   fail = term_add_node(&term_node, TERM_TTY, (int)NULL, pthread_self());

   if (fail == -1)
   {
      if (pthread_mutex_unlock(&terms->mutex) != 0)
         thread_error("th_tty_peer pthread_mutex_unlock",errno);
      th_tty_peer_exit(term_node);
   }

   if (term_node == NULL)
   {
      write_log(1,"Ouch!! No more than %d %s accepted!!\n",
                  term_type[TERM_TTY].max, term_type[TERM_TTY].name);
      
      if (pthread_mutex_unlock(&terms->mutex) != 0)
         thread_error("th_tty_peer pthread_mutex_unlock",errno);
      th_tty_peer_exit(term_node);
   }

   tty = term_node->specific;

   memcpy(tty,tty_tmp,sizeof(struct term_tty));    

    this_time = time(NULL);
   
#ifdef HAVE_CTIME_R
#ifdef SOLARIS
    ctime_r(&this_time,term_node->since, sizeof(term_node->since));
#else
    ctime_r(&this_time,term_node->since);
#endif
#else
    pthread_mutex_lock(&mutex_ctime);
    strncpy(term_node->since, ctime(&this_time), sizeof(term_node->since));   
    pthread_mutex_unlock(&mutex_ctime);
#endif

    /* Just to remove the cr+lf...*/
    term_node->since[sizeof(term_node->since)-2] = 0;

    /* This is a tty so, man... ;) */
    strncpy(term_node->from_ip, "127.0.0.1", sizeof(term_node->from_ip));

   /* Parse config file */
   if (strlen(tty_tmp->config_file))
      if (parser_read_config_file(tty_tmp, term_node) < 0)
      {
         write_log(0, "Error reading configuration file\n");
         th_tty_peer_exit(term_node);
      }
   
    if (init_attribs(term_node) < 0)        
    {
       if (pthread_mutex_unlock(&terms->mutex) != 0)
         thread_error("th_tty_peer pthread_mutex_unlock",errno);
       th_tty_peer_exit(term_node);
    }

    arguments = args;
    
    /* In command line mode we initialize the values by default */
    if (protocols[arguments->proto_index].init_attribs)
    {
        fail = (*protocols[arguments->proto_index].init_attribs)
            (term_node);
    } else
        write_log(0, "Warning, proto %d has no init_attribs function!!\n", arguments->proto_index);

    /* Choose a parser */
    fail = parser_cl_proto(term_node, arguments->count, arguments->argv_tmp, arguments->proto_index);

   if (pthread_mutex_unlock(&terms->mutex) != 0)
      thread_error("th_tty_peer pthread_mutex_unlock",errno);
   
   if (fail < 0) {
       write_log(0, "Error when parsing...\n");
       th_tty_peer_exit(term_node);
   }
      
   write_log(0, "Entering command line mode...\n");
   /* Execute attack... */
   doloop(term_node, arguments->proto_index);
   
   th_tty_peer_exit(term_node);
   
   return(NULL);
}

/*
 * We arrived here due to normal termination
 * from thread tty peer main routine...
 * Release resources and delete acquired terminal...
 */
void
th_tty_peer_exit(struct term_node *term_node)
{
   dlist_t *p;
   struct interface_data *iface_data;

   if (term_node)
   {
      for (p = term_node->used_ints->list; p; p = dlist_next(term_node->used_ints->list, p)) {
         iface_data = (struct interface_data *) dlist_data(p);
         interfaces_disable(iface_data->ifname);
      }
      
      attack_kill_th(term_node,ALL_ATTACK_THREADS);
      
      if (pthread_mutex_lock(&terms->mutex) != 0)
         thread_error("th_tty_peer pthread_mutex_lock",errno);
      
      term_delete_node(term_node, NOKILL_THREAD);               

      if (pthread_mutex_unlock(&terms->mutex) != 0)
         thread_error("th_tty_peer pthread_mutex_unlock",errno);
   }

   write_log(0,"\n th_tty_peer %d finished...\n",(int)pthread_self());      

   terms->work_state = STOPPED;

   pthread_exit(NULL); 
}


/*
 * David, pon algo coherente!!!
 */
void
doloop(struct term_node *node, int mode)
{
    struct term_tty *term_tty;
    struct attack *theattack = NULL;
    struct timeval timeout;
    fd_set read_set;
    int ret, fail;
    struct termios old_term, term;
    
    term_tty = node->specific;

    theattack = protocols[mode].attacks;

    if (term_tty->attack >= 0) 
    {
        if (theattack[term_tty->attack].nparams)
        {
            printf("\n<*> Ouch!! At the moment the command line interface doesn't support attacks <*>\n");
            printf("<*> that needs parameters and the one you've choosed needs %d <*>\n",
                         theattack[term_tty->attack].nparams);
        }
        else
        {
            printf("<*> Starting %s attack %s...\n", 
                (theattack[term_tty->attack].type)?"DOS":"NONDOS",
                theattack[term_tty->attack].s); 

            if (attack_launch(node, mode, term_tty->attack, NULL, 0) < 0)
                write_log(1, "Error launching attack %d (mode %d)!!\n", 
                            term_tty->attack, mode);

            fflush(stdin); fflush(stdout);
            setvbuf(stdout, NULL, _IONBF, 0);
            tcgetattr(0,&old_term);
            tcgetattr(0,&term);
            term.c_cc[VMIN]  = 1;
            term.c_cc[VTIME] = _POSIX_VDISABLE;
            term.c_lflag &= ~ICANON;
            term.c_lflag &= ~ECHO;
            tcsetattr(0,TCSANOW,&term);

            if (theattack[term_tty->attack].single == CONTINOUS) {
                printf("<*> Press any key to stop the attack <*>\n");
                fail = 0;
                while(!fail && !node->thread.stop)
                {
                    FD_ZERO(&read_set);
                    FD_SET(0, &read_set);
                    timeout.tv_sec  = 0;
                    timeout.tv_usec = 200000;
                    if ( (ret=select(1, &read_set, NULL, NULL, &timeout) ) == -1 )
                    {
                       thread_error("network_peer_th select()",errno);
                       continue;
                    }

                    if ( !ret )  /* Timeout, decrement timers... */
                       continue;
                    else
                    {
                       if (FD_ISSET(0, &read_set))
                       {
                          getchar();
                          fail = 1;
                       }
                    }
                 }
             } else
                /* Command line, only one attack (0), let's wait for its conclusion... */
                while (node->protocol[mode].attacks[0].up)
                    thread_usleep(150000);
             
             tcsetattr(0,TCSANOW, &old_term);
        }         
    } /* if term_tty->attack */
}


/*
 * Uptime thread...
 */
void *
th_uptime(void *arg)
{
   int ret,n;
   struct timeval timeout;
   sigset_t mask;

write_log(0,"\n th_uptime thread = %d\n",(int)pthread_self());

   sigfillset(&mask);

   if (pthread_sigmask(SIG_BLOCK, &mask, NULL))
   {
      thread_error("th_uptime pthread_sigmask()",errno);
      th_uptime_exit();
   }

   if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL))
   {
      thread_error("th_uptime pthread_setcancelstate()",errno);
      th_uptime_exit();
   }

   pthread_cleanup_push( &th_uptime_clean, (void *)NULL );
   
   if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL))
   {
      thread_error("th_uptime pthread_setcancelstate()",errno);
      th_uptime_exit();
   }

   if (pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL))
   {
      n=errno;
      pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
      thread_error("th_uptime pthread_setcanceltype()",n);
      th_uptime_exit();
   }

   while(1)
   {
      timeout.tv_sec  = 1;
      timeout.tv_usec = 0;

      if ( (ret=select( 0, NULL, NULL, NULL, &timeout ) ) == -1 )
      {
         n=errno;
         thread_error("th_uptime select()",n);
         continue;
      }

      if ( !ret )  /* Timeout, update uptime... */
         uptime++; 
   }

   pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);         

   pthread_cleanup_pop(0);

   return (NULL);
}


/*
 * We arrived here due to normal termination
 * from thread uptime main routine...
 */ 
void
th_uptime_exit(void)
{
   terms->uptime_th.id = 0;
   pthread_exit(NULL);
}


/*
 * We arrived here due to cancellation request...
 */
void
th_uptime_clean(void *data)
{
   terms->uptime_th.id = 0;
}



/*
 * Child will become a daemon so we need to kill parent
 * who is waiting on a loop...
 */
void
become_daemon(pid_t parent_id)
{
   thread_usleep(800000); /* Just for giving time to parent... */

   kill(parent_id,SIGUSR1); /* Kill parent... */
   
   setsid(); /* i wanna be a "session leader"... */

   chdir("/tmp"); /* If you wanna work... */

   umask(022); /* Just in case... */
}



/*
 * Write to stdout and logfile (mode=1), 
 * to logfile only (mode=0)
 * to stdout only (mode=2)           
 */ 
void
write_log( u_int16_t mode, char *msg, ... )
{
    va_list ap; /* Variable argument list...*/
#ifdef HAVE_GTK
	char buffer[4096];
	GtkTextIter iter2;
#endif

    va_start(ap,msg);

    if (mode && !tty_tmp->daemonize)
        vfprintf(stdout, msg, ap);

    if ((!mode || (mode == 1)) && (tty_tmp->log_file))
       vfprintf(tty_tmp->log_file, msg,ap);

	/* Send yersinia log to the main_log gtk widget */
#ifdef HAVE_GTK
    if ((!mode || (mode == 1)) && ((tty_tmp->gtk) && (tty_tmp->buffer_log))) {
       vsnprintf(buffer, 4096, msg,ap);
	   gtk_text_buffer_get_iter_at_offset (GTK_TEXT_BUFFER (tty_tmp->buffer_log), &iter2, 0);
	   gtk_text_buffer_insert(GTK_TEXT_BUFFER(tty_tmp->buffer_log), &iter2, buffer, -1);
	}
#endif

    va_end(ap);
}



/*
 * Exit from program printing the 
 * system error.                  
 */
void
go_out_error( int8_t *msg, int32_t errn )
{
#ifdef HAVE_GLIBC_STRERROR_R
  /* At least on glibc >= 2.0 Can anybody confirm?... */
  char buf[64];
  
  write_log(1,"%s: %s -> %s\n", PACKAGE, msg, 
              strerror_r(errn,buf,sizeof(buf)));
#else

#ifdef HAVE_STRERROR
   write_log(1,"%s: %s -> %s\n", PACKAGE, msg, strerror(errn) );
#else
   write_log(1,"%s: %s -> %s\n", PACKAGE, msg, sys_errlist[errn] );
#endif

#endif

   g00dbye();
}


/*
 * Exit from program printing     
 * a custom error message.        
 */
void
go_out( char *msg, ... )
{
    va_list ap; /* Variable argument list...*/

    if (msg)
    {
        va_start(ap,msg);

        vfprintf(stderr, msg, ap);
    }

    g00dbye();
}


/* 
 * Exit function when nothing has been initialized
 */
void
clean_exit(void)
{
    if (tty_tmp)
    {
       if (tty_tmp->term)
          free(tty_tmp->term);
       free(tty_tmp);
    }
    
    show_vty_motd();
    
    fflush(stdout);
    
    exit(0);
}

/*
 * Last exit routine...
 * Use global *tty_tmp and terms[]
 */
void 
g00dbye(void)
{
    write_log(0," g00dbye function called from %d\n",(int)pthread_self());
    
    term_delete_all_tty();
    
#ifdef HAS_CURSES
    if (tty_tmp->interactive && (terms->gui_th.id != 0))
       thread_destroy(&terms->gui_th);
#endif

#ifdef HAVE_GTK
    if (tty_tmp->gtk && (terms->gui_gtk_th.id != 0)) {
       thread_destroy(&terms->gui_gtk_th);
    }
#endif

#ifdef HAVE_REMOTE_ADMIN
    if (tty_tmp->daemonize)
       admin_exit();
#endif

   /* Kill Uptime thread... */
   if (terms->uptime_th.id)
      thread_destroy_cancel(terms->uptime_th.id);
    
   if (tty_tmp && tty_tmp->term)
      free(tty_tmp->term);

   /* Destroy interfaces only if they are initialized!! */
   if (terms) 
      interfaces_destroy(&terms->pcap_listen_th);

   protocol_destroy();

   if (terms)
      term_destroy();
   
   if (!tty_tmp->daemonize)
   {
      write_log(0, " Showing MOTD..\n");
      show_vty_motd();
   }

   finish_log();

   if (tty_tmp)
      free(tty_tmp);

   exit(0);
}




/*
 * Init the log file. 
 */
void
init_log(void)
{
    char this_name[128];
    time_t this_time;

    this_time = time(NULL);

    gethostname(this_name, sizeof(this_name));

    write_log(0,"# %s v%s started in %s on %s", PACKAGE, VERSION, 
                   this_name, ctime(&this_time));

    write_log(0,"\n");
}


/*
 * Finish the log file. 
 */
void
finish_log(void)
{
    time_t this_time;
    this_time = time(NULL);

    write_log(0,"# %s finished on %s\n",PACKAGE, ctime(&this_time));

    fflush(tty_tmp->log_file);
    if (fclose(tty_tmp->log_file) < 0)
        thread_error("Error in fclose", errno);
}



/*
 * Initialize default values 
 * on connection struct      
 */
int8_t
init_attribs(struct term_node *node)
{
    int8_t i, result;

    result = 0;

    for (i = 0; i < MAX_PROTOCOLS; i++) 
    {
        if (!protocols[i].visible)
           continue;
        if (protocols[i].init_attribs)
	   result = result | (*protocols[i].init_attribs)(node);
        else
           write_log(0, "Warning: protocol %d has no init_attribs function!!\n", i);
    }

    return result;
}


/*
 * Let's handle signals 
 */
void 
handle_signals( void )
{
    posix_signal(SIGIO,   SIG_IGN);
    posix_signal(SIGURG,  SIG_IGN);
    posix_signal(SIGTSTP, SIG_IGN);
    posix_signal(SIGQUIT, SIG_IGN);
    posix_signal(SIGPIPE, SIG_IGN);
#if !defined(OPENBSD) && !defined(FREEBSD) && !defined(DARWIN)
    posix_signal(SIGPOLL, SIG_IGN);
#endif
    posix_signal(SIGCHLD, SIG_IGN);
    posix_signal(SIGUSR1, SIG_IGN);
    posix_signal(SIGUSR2, SIG_IGN);
    posix_signal(SIGINT,  SIG_IGN);
    posix_signal(SIGTERM, SIG_IGN);
    posix_signal(SIGHUP,  SIG_IGN);
    posix_signal(SIGALRM, SIG_IGN);
}


/*
 * Handling signals on parent
 */
void 
handle_signals_parent( void )
{
    posix_signal( SIGIO,   SIG_IGN );
    posix_signal( SIGURG,  SIG_IGN );
    posix_signal( SIGTSTP, SIG_IGN );
    posix_signal( SIGQUIT, SIG_IGN );
    posix_signal( SIGPIPE, SIG_IGN );
#if !defined(OPENBSD) && !defined(FREEBSD) && !defined(DARWIN)
    posix_signal( SIGPOLL, SIG_IGN );
#endif
    posix_signal( SIGUSR1, final_parent );
    posix_signal( SIGUSR2, SIG_IGN );
    posix_signal( SIGINT,  SIG_IGN );
    posix_signal( SIGTERM, SIG_IGN );
    posix_signal( SIGHUP,  SIG_IGN );
}



/*
 * POSIX functions for signals 
 */
int 
posix_signal( int signo, void (*handler)() )
{
    struct sigaction act;

    act.sa_handler = handler;
    act.sa_flags = 0;
    sigemptyset( &act.sa_mask );

    switch( signo )
    {
        case SIGALRM: break;
        case   SIGIO:
        case  SIGHUP:
        case SIGUSR2: sigaddset( &act.sa_mask, SIGALRM );
        default: act.sa_flags |= SA_RESTART;
                 break;
    }

    if ( sigaction( signo, &act, NULL ) == -1 )
        return -1;

    return 0;
}



/*
 * SIGINT/SIGTERM/SIGHUP handler 
 */
void 
final( int signal )
{
    write_log(1,"\nTERM signal received from %d!\n", (int)pthread_self());
    g00dbye();
}


/*
 * Show the vty motd...
 * Return -1 if error. 0 if Ok.
 */
int8_t
show_vty_motd()
{
   int8_t j;

   j = term_motd();

   if (j < 0)
      return -1;
      
   printf("%s", vty_motd[j]);
   
   return 0;
}



/*
 * SIGUSR1 parent handler
 */
void
final_parent(int signal)
{
   tcsetattr(0, TCSANOW, &term_parent);
   exit(0);
}


