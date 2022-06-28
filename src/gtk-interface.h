/* gtk_interface.h
 * Definitions for GTK Interfaces
 *
 * Yersinia
 * By David Barroso <tomac@yersinia.net> and Alfredo Andres <aandreswork@hotmail.com>
 * Copyright 2005-2017 Alfredo Andres and David Barroso
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

#ifndef __GTK_INTERFACE_H__
#define __GTK_INTERFACE_H__

#include "gtk-callbacks.h"
#include "gtk-support.h"

static GtkWidget *protocols_tree[MAX_PROTOCOLS + 1];
static GtkListStore *protocols_tree_model[MAX_PROTOCOLS + 1];

GtkWidget* gtk_i_create_Main (struct gtk_s_helper *);
GtkWidget* gtk_i_create_opendialog (struct gtk_s_helper *);
GtkWidget* gtk_i_create_savedialog (struct gtk_s_helper *);
GtkWidget* gtk_i_create_capturedialog (struct gtk_s_helper *);
void gtk_i_create_aboutdialog( GtkMenuItem *menuitem, gpointer user_data );
GtkWidget* gtk_i_create_attacksdialog (GtkWidget *, struct gtk_s_helper *, u_int8_t);
GtkWidget* create_viewpacketdialog (void);
GtkWidget* create_interfacesdialog (struct term_node *);
GtkWidget* gtk_i_create_listattacksdialog (struct term_node *);
GtkWidget* create_infodialog (void);
GtkWidget* gtk_i_create_warningdialog (char *, ...);
GtkWidget* gtk_i_create_extradialog (struct gtk_s_helper *);
GtkWidget* gtk_i_create_add_extradialog (struct gtk_s_helper *, u_int8_t);
GtkWidget* gtk_i_create_attackparamsdialog( GTK_ATTACK_PARAMS_CONTEXT * );
GtkWidget* create_protocol_mwindow(GtkWidget *, struct gtk_s_helper *, u_int8_t);
void gtk_i_view_menu(GtkWidget *, GtkWidget *, GdkEventButton *, struct gtk_s_helper *);
void gtk_i_modaldialog( int msg_type, char *header, char *msg, ...);

/* For the credits comments */
extern int8_t term_motd(void);
extern char *vty_motd[];

#endif
