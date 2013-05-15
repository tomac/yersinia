/* gtk_callbacks.h
 * Definitions GTK callbacks
 *
 * $Id: gtk-callbacks.h 43 2007-04-27 11:07:17Z slay $ 
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

#ifndef __GTK_CALLBACKS_H__
#define __GTK_CALLBACKS_H__

#include "terminal-defs.h"
#include "interfaces.h"
#include "attack.h"

#include <gtk/gtk.h>

#include "gtk-gui.h"
#include "gtk-interface.h"
#include "gtk-support.h"

/* Global extern */
extern struct term_tty *tty_tmp;
extern int8_t parser_read_config_file(struct term_tty *, struct term_node *);
extern int8_t parser_write_config_file(struct term_tty *);

/* Functions prototypes */
void gtk_c_on_file_open_activate(GtkMenuItem *, gpointer);
void gtk_c_on_file_save_activate(GtkMenuItem *, gpointer);
void gtk_c_opendialog_open(GtkWidget *, gpointer);
void gtk_c_savedialog_save(GtkWidget *, gpointer);
void gtk_c_on_file_quit_activate(GtkMenuItem *, gpointer);
void
on_protocols_proto1_activate           (GtkMenuItem     *menuitem,
                                        gpointer         user_data);
void gtk_c_on_protocols_toggle(GtkMenuItem *, gpointer);
void gtk_c_on_actions_execute_activate(GtkMenuItem *, gpointer);
void gtk_c_on_actions_interfaces_activate(GtkMenuItem *, gpointer);
void gtk_c_on_menu_actions_load_default_activate (GtkMenuItem *menuitem, gpointer);
void gtk_c_on_menu_actions_list_attacks_activate (GtkMenuItem *menuitem, gpointer);
void on_menu_actions_clear_activate (GtkMenuItem *, GtkWidget *);
void gtk_c_on_menu_options_edit_toggle (GtkWidget *, gpointer);
void on_menu_options_macspoofing_toggle (GtkCheckMenuItem *, struct term_node *);
void on_help_about_activate(GtkMenuItem *menuitem, gpointer user_data);
void gtk_c_on_actions_clear_activate(GtkMenuItem *, gpointer);
void gtk_c_on_capture_activate(GtkMenuItem *, gpointer);
void gtk_c_capturedialog_save(GtkWidget *, gpointer);
void gtk_c_attacks_synchro(GtkNotebook *, GtkNotebookPage *, guint,  gpointer);
void gtk_c_attacks_radio_changed(GtkWidget *, gpointer);
void gtk_c_attacks_launch(GtkWidget *, gpointer);
void gtk_c_attackparams_launch(GtkWidget *, gpointer);
void gtk_c_listattacks_destroyall(GtkWidget *, gpointer);
void gtk_c_update_hexview(GtkTreeSelection *, gpointer);
void gtk_c_clock_update(GtkWidget *);
void gtk_c_tree_update(GtkWidget *);
void gtk_c_refresh_mwindow_notebook(GtkNotebook *, GtkNotebookPage *, guint,  gpointer);
gboolean gtk_c_refresh_mwindow(gpointer);
void gtk_c_tree_selection_changed_cb (GtkTreeSelection *, gpointer);
void gtk_c_toggle_interface(GtkWidget *, struct term_node *);
gboolean gtk_c_view_onPopupMenu(GtkWidget *, gpointer);
void gtk_c_view_popup_menu(GtkWidget *, gpointer);
gboolean gtk_c_view_onButtonPressed (GtkWidget *treeview, GdkEventButton *event, gpointer userdata);
void gtk_c_on_extra_button_clicked(GtkButton *, gpointer);
void gtk_c_extra_button_add_clicked(GtkButton *, gpointer);
void gtk_c_add_extra_button_add_ok_clicked(GtkButton *, gpointer);

/* External functions */
extern void write_log( u_int16_t mode, char *msg, ... );

#endif
/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
