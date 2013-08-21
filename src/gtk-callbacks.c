/* gtk_callbacks.c
 * GTK Callbacks
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
"$Id: gtk-callbacks.c 48 2007-05-08 09:41:17Z slay $";
#endif


#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <time.h>

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif

#include <gtk/gtk.h>

#include "gtk-callbacks.h"

#define GLADE_HOOKUP_OBJECT(component,widget,name) \
  g_object_set_data_full (G_OBJECT (component), name, \
    gtk_widget_ref (widget), (GDestroyNotify) gtk_widget_unref)

#define GLADE_HOOKUP_OBJECT_NO_REF(component,widget,name) \
  g_object_set_data (G_OBJECT (component), name, widget)

void
gtk_c_on_file_open_activate(GtkMenuItem *menuitem, gpointer user_data)
{
   GtkWidget *dialog;
   struct gtk_s_helper *helper;

   helper = (struct gtk_s_helper *)user_data;
   dialog = gtk_i_create_opendialog(helper);
   gtk_widget_show(dialog);
}


void
gtk_c_on_file_save_activate(GtkMenuItem *menuitem, gpointer user_data)
{
   GtkWidget *dialog;
   struct gtk_s_helper *helper;

   helper = (struct gtk_s_helper *)user_data;
   dialog = gtk_i_create_savedialog(helper);
   gtk_widget_show(dialog);
}


void
gtk_c_opendialog_open(GtkWidget *button, gpointer userdata)
{
   GtkWidget *dialog;
   struct gtk_s_helper *helper;
   char *filename;
   u_int8_t i;

   helper = (struct gtk_s_helper *)userdata;
   dialog = lookup_widget(GTK_WIDGET(button), "opendialog");
   filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));

   if (strlen(filename))  {
      strncpy(tty_tmp->config_file, filename, FILENAME_MAX);

      if (parser_read_config_file(tty_tmp, helper->node) < 0) {
         gtk_i_create_warningdialog("%s", "Error reading config file");
      }

      /* When parsing the configuration file, everything is updated in protocol[i].default_values, so
       * now we need to copy it to the current node */
      for (i = 0; i < MAX_PROTOCOLS; i++) 
         if (protocols[i].visible)
            memcpy((void *)helper->node->protocol[i].tmp_data, (void *)protocols[i].default_values, protocols[i].size);

      g_free(filename);
   }

   gtk_statusbar_push(GTK_STATUSBAR(helper->statusbar), 0, "Configuration file read");

   gtk_widget_destroy(GTK_WIDGET(dialog));
}


void
gtk_c_savedialog_save(GtkWidget *button, gpointer userdata)
{
   GtkWidget *dialog;
   struct gtk_s_helper *helper;
   char *filename;
   u_int8_t i;

   helper = (struct gtk_s_helper *)userdata;
   dialog = lookup_widget(GTK_WIDGET(button), "savedialog");
   filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));

   if (strlen(filename))  {
      strncpy(tty_tmp->config_file, filename, FILENAME_MAX);

      for (i = 0; i < MAX_PROTOCOLS; i++)
         if (protocols[i].visible)
            memcpy((void *)protocols[i].default_values, (void *)helper->node->protocol[i].tmp_data, protocols[i].size);
           
      strncpy(tty_tmp->config_file, filename, FILENAME_MAX);

      if (parser_write_config_file(tty_tmp) < 0) {
         gtk_i_create_warningdialog("%s", "Error writing config file");
      }

      g_free(filename);
   }

   gtk_statusbar_push(GTK_STATUSBAR(helper->statusbar), 0, "Configuration file written");

   gtk_widget_destroy(GTK_WIDGET(dialog));
}


void gtk_c_on_file_quit_activate(GtkMenuItem *menuitem, gpointer user_data)
{
   struct gtk_s_helper *helper;

   helper = (struct gtk_s_helper *)user_data;
   gtk_statusbar_push(GTK_STATUSBAR(helper->statusbar), 0, "Exiting... be patient");
   
   gtk_main_quit();
}


void
on_protocols_proto1_activate           (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
}


void
gtk_c_on_protocols_toggle(GtkMenuItem *menuitem, gpointer user_data)
{
    GtkWidget *n_label, *notebook, *main_statusbar;
    u_int8_t *n_mode;

    n_mode = (u_int8_t *) user_data;
    notebook = lookup_widget(GTK_WIDGET(menuitem), "main_vhv2_notebook");
    n_label = gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), *n_mode);
    main_statusbar = lookup_widget(GTK_WIDGET(notebook), "main_statusbar");
    write_log(0, "joe, voy a hacer algo con %d\n", *n_mode);

    if (gtk_check_menu_item_get_active(GTK_CHECK_MENU_ITEM(menuitem))) {
       gtk_statusbar_push(GTK_STATUSBAR(main_statusbar), 0, "Closing protocol");
       gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(menuitem), FALSE);
       gtk_widget_hide(n_label);
    } else {
       gtk_statusbar_push(GTK_STATUSBAR(main_statusbar), 0, "Opening protocol");
       gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(menuitem), TRUE);
       gtk_widget_show(n_label);
    }
}


void
gtk_c_on_actions_execute_activate(GtkMenuItem *menuitem, gpointer user_data)
{
   GtkWidget *window, *notebook;
   struct gtk_s_helper *helper;
   u_int8_t mode;

   helper = (struct gtk_s_helper *)user_data;
   notebook = lookup_widget(GTK_WIDGET(menuitem), "main_vhv2_notebook");
   mode = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));

   window = gtk_i_create_attacksdialog(notebook, helper, mode);
   gtk_widget_show(window);
}


void
gtk_c_on_actions_interfaces_activate (GtkMenuItem *menuitem, gpointer user_data)
{
   GtkWidget *window;
   struct gtk_s_helper *helper;

   helper = (struct gtk_s_helper *)user_data;
   window = create_interfacesdialog(helper->node);
   gtk_widget_show(window);
}


void
gtk_c_on_menu_actions_load_default_activate (GtkMenuItem *menuitem, gpointer user_data)
{
    GtkWidget *notebook;
    struct gtk_s_helper *helper;
    u_int8_t mode;

    helper = (struct gtk_s_helper *) user_data;
    notebook = lookup_widget(GTK_WIDGET(menuitem), "main_vhv2_notebook");
    mode = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));

    if (protocols[mode].init_attribs)
       (*protocols[mode].init_attribs)(helper->node);
    else {
       write_log(0, "Warning: no init_attribs for mode %d\n", mode);
    }

    gtk_statusbar_push(GTK_STATUSBAR(helper->statusbar), 0, "Loading protocol default values...");
}


void
gtk_c_on_menu_actions_list_attacks_activate (GtkMenuItem *menuitem, gpointer user_data)
{
   GtkWidget *window;
   GtkWidget *notebook;
   struct gtk_s_helper *helper;
   u_int8_t mode;

   helper = (struct gtk_s_helper *)user_data;
   notebook = lookup_widget(GTK_WIDGET(menuitem), "main_vhv2_notebook");
   mode = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));

   window = gtk_i_create_listattacksdialog(helper->node);
   gtk_widget_show(window);
}


void
gtk_c_on_actions_clear_activate(GtkMenuItem *menuitem, gpointer user_data)
{
   struct gtk_s_helper *helper;
   u_int8_t i;
   char buffer[64];

   helper = (struct gtk_s_helper *)user_data;
   if (strcmp("ALL", gtk_widget_get_name(GTK_WIDGET(menuitem))) == 0)
       helper->extra = PROTO_ALL;
   else {
      i = 0;
      while(protocols[i].namep) {
         if(strcmp(protocols[i].namep, gtk_widget_get_name(GTK_WIDGET(menuitem))) == 0) {
            helper->extra = i;
            break;
         }
         i++;
      }
   }
   interfaces_clear_stats(helper->extra);
   snprintf(buffer, 64, "Clearing stats for mode %s...", gtk_widget_get_name(GTK_WIDGET(menuitem)));
   gtk_statusbar_push(GTK_STATUSBAR(helper->statusbar), 0, buffer);
}


void
gtk_c_on_capture_activate(GtkMenuItem *menuitem, gpointer user_data)
{
   GtkWidget *dialog;
   struct gtk_s_helper *helper;
   u_int8_t i;

   helper = (struct gtk_s_helper *)user_data;
   if (strcmp("ALL", gtk_widget_get_name(GTK_WIDGET(menuitem))) == 0)
       helper->extra = PROTO_ALL;
   else {
      i = 0;
      while(protocols[i].namep) {
         if(strcmp(protocols[i].namep, gtk_widget_get_name(GTK_WIDGET(menuitem))) == 0) {
            helper->extra = i;
            break;
         }
         i++;
      }
   }
   dialog = gtk_i_create_capturedialog(helper);
   gtk_widget_show(dialog);
}


void
gtk_c_capturedialog_save(GtkWidget *button, gpointer userdata)
{
   GtkWidget *dialog;
   struct gtk_s_helper *helper;
   char *filename;
   u_int8_t iface;
   pcap_dumper_t *pdumper;
   dlist_t *p;
   struct interface_data *iface_data;

   helper = (struct gtk_s_helper *)userdata;
   dialog = lookup_widget(GTK_WIDGET(button), "savedialog");
   filename = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));

   if (helper->extra == PROTO_ALL) {
      pdumper = helper->node->pcap_file.pdumper;
      iface = interfaces_get_last_int(PROTO_ALL);
   } else {
      pdumper = helper->node->protocol[helper->extra].pcap_file.pdumper;
      iface = interfaces_get_last_int(helper->extra);
   }

   if (pdumper) {
      gtk_i_create_warningdialog("%s", "Error: pcap_file is in use");
      return;
   }

   /* Take the first active interface for saving data */
   p = interfaces->list;
   while(p) {
      iface_data = (struct interface_data *) dlist_data(p);
      if (iface_data->up) {
         if (filename[0] && interfaces_pcap_file_open(helper->node, helper->extra, filename, iface_data->ifname) < 0)
         {
            write_log(0, "Error opening file %s to save pcap data\n", filename);
            gtk_gui_th_exit(helper->node); 
         }
         break;
      }
      else
         p = dlist_next(interfaces->list, p);
   }

   /* No interface found*/
   if (p == NULL)
      gtk_i_create_warningdialog("%s", "Error: there is no active interface");

   g_free(filename);

   gtk_widget_destroy(GTK_WIDGET(dialog));
}


void
gtk_c_attacks_synchro(GtkNotebook *attacks_notebook, GtkNotebookPage *page, guint npage, gpointer userdata)
{
   GtkNotebook *notebook;

   notebook = (GtkNotebook *)userdata;

   gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook), npage);
}


void
gtk_c_attacks_radio_changed(GtkWidget *radio, gpointer userdata)
{
   u_int8_t i;
   struct gtk_s_helper *helper;

   if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(radio))) {
      helper = (struct gtk_s_helper *) userdata;
      i = 0;
      while(protocols[helper->mode].attacks[i].s) {
         if (strcmp(gtk_button_get_label(GTK_BUTTON(radio)), protocols[helper->mode].attacks[i].s) == 0) {
            helper->row = i;
            helper->attack = (struct attack *) &protocols[helper->mode].attacks[i];
            break;
    }
         i++;
      }
   }
}


void
gtk_c_attacks_launch(GtkWidget *button, gpointer userdata)
{
   struct gtk_s_helper *helper;
   GtkWidget *attacksdialog;
   GtkWidget *attackparamsdialog;

   helper = (struct gtk_s_helper *)userdata;
   attacksdialog = lookup_widget(GTK_WIDGET(button), "attacksdialog");

   if ((helper->attack) && (helper->attack->nparams)) {
      if ((helper->attack_param = calloc(1, (sizeof(struct attack_param) * helper->attack->nparams))) == NULL)
      {
         thread_error(" ncurses_i_attack_screen attack_param calloc",errno);
         return;
      }

      memcpy(helper->attack_param, (void *)(helper->attack->param), sizeof(struct attack_param) * helper->attack->nparams);

      if (attack_init_params(helper->node, helper->attack_param, helper->attack->nparams) < 0) {
         free(helper->attack_param);
         return;
      }

      attackparamsdialog = gtk_i_create_attackparamsdialog(helper, helper->attack_param, helper->attack->nparams);
      gtk_widget_show(attackparamsdialog);

   } else {
      if (attack_launch(helper->node, helper->mode, helper->row, NULL, 0) < 0)
         write_log(0, "Error launching attack %d", helper->row);
   }

   gtk_widget_destroy(attacksdialog);
}


void
gtk_c_attackparams_launch(GtkWidget *button, gpointer userdata)
{
   GtkWidget *widget, *warning;
   struct gtk_s_helper *helper;
   char tmp_name[3], *text;
   u_int8_t i, field;

   helper = (struct gtk_s_helper *) userdata;

   for (i=0; i < helper->attack->nparams; i++) {
      snprintf(tmp_name, 3, "%02d", i);
      widget = lookup_widget(GTK_WIDGET(button), tmp_name);

      text = (char *) gtk_entry_get_text(GTK_ENTRY(widget));
      strncpy(helper->attack_param[i].print, text, helper->attack->param[i].size_print);
   }

   if (attack_filter_all_params(helper->attack_param, helper->attack->nparams, &field) < 0) {
      warning = gtk_i_create_warningdialog("Bad data on field %s!!", helper->attack->param[field].desc);
      gtk_widget_show(warning);
   } else {
      if (attack_launch(helper->node, helper->mode, helper->row, helper->attack_param, helper->attack->nparams) < 0)
         write_log(0, "Error launching attack %d", helper->row);
   }
}


void
gtk_c_listattacks_destroyall(GtkWidget *button, gpointer userdata)
{
   struct term_node *node;
   GtkWidget *listattacksdialog;

   node = (struct term_node *) userdata;
   listattacksdialog = lookup_widget(GTK_WIDGET(button), "listattacksdialog");

   attack_kill_th(node, ALL_ATTACK_THREADS);

   gtk_widget_destroy(GTK_WIDGET(listattacksdialog));
}


void
gtk_c_update_hexview(GtkTreeSelection *selection, gpointer userdata)
{
   GtkWidget *textview;
   GtkTextBuffer *buffer;
   GtkTreeIter iter;
   GtkTextIter iter2, start, end;
   GtkTreeModel *model;
   struct gtk_s_helper *helper;
   u_int8_t row, mode, *packet;
   u_int16_t length, oset;
   int32_t j, line;
   register u_int i;
   register int s1, s2;
   register int nshorts;
   char hexstuff[HEXDUMP_SHORTS_PER_LINE*HEXDUMP_HEXSTUFF_PER_SHORT+1], *hsp;
   char asciistuff[ASCII_LINELENGTH+1], *asp;
   char tmp_str[70];
   u_int32_t maxlength = HEXDUMP_SHORTS_PER_LINE;
   gchar *out;

   j = 0;
   line = 0;
   oset = 0;
   length = 0;
   packet = NULL;

   helper = (struct gtk_s_helper *) userdata;
   textview = lookup_widget(GTK_WIDGET(helper->notebook), "main_vhv2_texthex");
   buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (textview));

   /* First delete the buffer */
   gtk_text_buffer_get_iter_at_offset (GTK_TEXT_BUFFER (buffer), &start, 0);
   gtk_text_buffer_get_iter_at_offset (GTK_TEXT_BUFFER (buffer), &end,
         gtk_text_buffer_get_char_count (GTK_TEXT_BUFFER (buffer)));

   gtk_text_buffer_delete (GTK_TEXT_BUFFER (buffer), &start, &end);

   /* We need to get the pointer to the packet selected in the other window */
   if (gtk_tree_selection_get_selected (selection, &model, &iter))
   {
      gtk_tree_model_get(model, &iter, 0, &row, -1);
   } else {/* TODO: do a proper select */
      row = 0;
   }

   gtk_text_buffer_get_iter_at_offset (GTK_TEXT_BUFFER (buffer), &iter2, 0);
   mode = gtk_notebook_get_current_page(GTK_NOTEBOOK(helper->notebook));

   packet = protocols[mode].stats[row].packet;
   length = (protocols[mode].stats[row].header->len < SNAPLEN) ? protocols[mode].stats[row].header->len : SNAPLEN;

   nshorts = length / sizeof(u_int16_t);
   i = 0;
   hsp = hexstuff; asp = asciistuff;
   while (--nshorts >= 0) {
      s1 = *packet++;
      s2 = *packet++;

      (void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
                     " %02x%02x", s1, s2);
      hsp += HEXDUMP_HEXSTUFF_PER_SHORT;
      *(asp++) = (isgraph(s1) ? s1 : '.');
      *(asp++) = (isgraph(s2) ? s2 : '.');
      i++;

      if (i >= maxlength) {
         *hsp = *asp = '\0';
         snprintf(tmp_str, 70, "0x%04x: %-*s  %s\n",
               oset, HEXDUMP_HEXSTUFF_PER_LINE,
               hexstuff, asciistuff);
         /* We need to convert to valid UTF-8; if not, it is not displayed :( */
         out = g_convert(tmp_str, -1,"UTF-8","ISO8859-1",NULL,NULL,NULL);

         if (out == NULL) {
            return; /* handle error */
         }
         gtk_text_buffer_insert(buffer, &iter2, out, -1);
         g_free(out);
         i = 0; hsp = hexstuff; asp = asciistuff;
         oset += HEXDUMP_BYTES_PER_LINE;
         j++;
      }
   }

   if (length & 1) {
      s1 = *packet++;
      (void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
                     " %02x", s1);
      hsp += 3;
      *(asp++) = (isgraph(s1) ? s1 : '.');
      ++i;
   }
   if (i > 0) {
      *hsp = *asp = '\0';
      snprintf(tmp_str, 70, "0x%04x: %-*s  %s\n",
            oset, HEXDUMP_HEXSTUFF_PER_LINE,
            hexstuff, asciistuff);
      /* We need to convert to valid UTF-8; if not, it is not displayed :( */
      out = g_convert(tmp_str, -1,"UTF-8","ISO8859-1",NULL,NULL,NULL);

      if (out == NULL) {
         return; /* handle error */
      }
      gtk_text_buffer_insert(buffer, &iter2, out, -1);
      g_free(out);
   }
}


void
on_menu_actions_clear_activate  (GtkMenuItem     *menuitem,
                                 GtkWidget       *notebook)
{
    GtkWidget *main_statusbar;
    u_int8_t mode;

    mode = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));
    main_statusbar = lookup_widget(GTK_WIDGET(notebook), "main_statusbar");
    interfaces_clear_stats(mode);
    gtk_statusbar_push(GTK_STATUSBAR(main_statusbar), 0, "Clearing Mode stats...");
}


void gtk_c_on_menu_options_edit_toggle (GtkWidget *menu, gpointer userdata)
{
   GtkWidget *notebook, *toolbar_edit, *widget, *warning;
   struct gtk_s_helper *helper;
   u_int8_t i, j, mode;
   struct commands_param *param;
   char tmp_name[5], *text;

   helper = (struct gtk_s_helper *)userdata;

   notebook = lookup_widget(GTK_WIDGET(menu), "main_vhv2_notebook");
   toolbar_edit = lookup_widget(GTK_WIDGET(menu), "toolbar_edit");
   mode = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));
   if (helper->edit_mode) {
      for(i = 0; i < MAX_PROTOCOLS; i++) {
         if (protocols[i].visible) {
            param = (struct commands_param *)protocols[i].parameters;
            for (j = 0; j < protocols[i].nparams; j++) {
               if ((param[j].type != FIELD_DEFAULT) && (param[j].type != FIELD_IFACE) && (param[j].type != FIELD_EXTRA)) {
                  snprintf(tmp_name, 5, "%02d%02d", i, j);
                  widget = lookup_widget(GTK_WIDGET(notebook), tmp_name);
                  text = (char *) gtk_entry_get_text(GTK_ENTRY(widget));
                  if (parser_filter_param(param[j].type, helper->node->protocol[i].commands_param[j],
                           text, param[j].size_print, param[j].size) < 0) {
                     warning = gtk_i_create_warningdialog("Bad Parameter %s with wrong value %s in protocol %s!", 
                           param[j].ldesc, text, protocols[i].namep);
                     gtk_widget_show(warning);
                     //break;
                  }
                  gtk_entry_set_editable(GTK_ENTRY(widget), FALSE);
               }
            }
         }
      }
      helper->edit_mode = 0;
      gtk_statusbar_push(GTK_STATUSBAR(helper->statusbar), 0, "Edit mode disabled");
   } else {
      helper->edit_mode = 1;
      for (i = 0; i < MAX_PROTOCOLS; i++) {
         if (protocols[i].visible) {
            param = (struct commands_param *)protocols[i].parameters;
            for (j = 0; j < protocols[i].nparams; j++) {
               if ((param[j].type != FIELD_DEFAULT) && (param[j].type != FIELD_IFACE) && (param[j].type != FIELD_EXTRA)) {
                  snprintf(tmp_name, 5, "%02d%02d", i, j);
                  widget = lookup_widget(GTK_WIDGET(notebook), tmp_name);
                  gtk_entry_set_editable(GTK_ENTRY(widget), TRUE);
               }
            }
         }
      }
      gtk_statusbar_push(GTK_STATUSBAR(helper->statusbar), 0, "Edit mode enabled");
   }
}


void on_menu_options_macspoofing_toggle (GtkCheckMenuItem *menu, struct term_node *node)
{
   GtkWidget *notebook, *main_statusbar;
   u_int8_t mode;

   notebook = lookup_widget(GTK_WIDGET(menu), "main_vhv2_notebook");
   mode = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));
   main_statusbar = lookup_widget(GTK_WIDGET(notebook), "main_statusbar");
   if (node->mac_spoofing) {
      node->mac_spoofing = 0;
      gtk_statusbar_push(GTK_STATUSBAR(main_statusbar), 0, "MAC Spoofing set to OFF");
      gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(menu), FALSE);
   } else {
      node->mac_spoofing = 1;
      gtk_statusbar_push(GTK_STATUSBAR(main_statusbar), 0, "MAC Spoofing set to ON");
      gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(menu), TRUE);
   }
}


void
on_help_about_activate(GtkMenuItem *menuitem, gpointer user_data)
{
   GtkWidget *aboutdialog;

   aboutdialog = gtk_i_create_aboutdialog();
   gtk_widget_show(aboutdialog);
}


void
gtk_c_clock_update(GtkWidget *clock)
{
   struct tm *aux;
   time_t this_time;
   char clock_str[10];

   this_time = time(NULL);

   aux = localtime(&this_time);

   if (aux != NULL)
      snprintf(clock_str, 10, "%02d:%02d:%02d", aux->tm_hour, aux->tm_min,
            aux->tm_sec);

   gtk_label_set_text((GtkLabel *)clock, clock_str);
}


void
gtk_c_tree_update(GtkWidget *tree_model)
{
  u_int8_t i, j;
  GtkTreeIter iter;
  GtkTreePath *path;
  char tmp[3];
  
  j = 0;
  for (i=0; i < MAX_PROTOCOLS; i++)
  {
    if (protocols[i].visible) {
      snprintf(tmp, 3, "%d", j);
      /* Modify a particular row */
      path = gtk_tree_path_new_from_string (tmp);
      gtk_tree_model_get_iter (GTK_TREE_MODEL (tree_model), &iter, path);
      gtk_tree_path_free (path);
      gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, 1, protocols[i].packets, -1);
      j++;
    }
  }

  snprintf(tmp, 3, "%d", j);
  path = gtk_tree_path_new_from_string(tmp);
  gtk_tree_model_get_iter (GTK_TREE_MODEL (tree_model), &iter, path);
  gtk_tree_path_free (path);
  gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, 1, packet_stats.global_counter.total_packets, -1);
}


void
gtk_c_refresh_mwindow_notebook(GtkNotebook *notebook, GtkNotebookPage *page, guint npage, gpointer userdata)
{
   struct gtk_s_helper *helper;

   helper = (struct gtk_s_helper *)userdata;
   helper->mode = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));

   /* Avoid Yersinia window log */
   if (helper->mode != MAX_PROTOCOLS) {
      gtk_c_tree_selection_changed_cb (helper->select, helper);
      gtk_c_update_hexview(helper->select, helper);
   }
   gtk_c_refresh_mwindow(helper);
}


gboolean
gtk_c_refresh_mwindow(gpointer userdata)
{
   u_int8_t i, j, k, val, tlv, mode;
   char *ptrtlv;
   char timebuf[19], meaningbuf[64], **values;
   struct commands_param *params;
   struct commands_param_extra *extra_params;
   struct tuple_type_desc *func;
   GtkTreeIter iter;
   GtkListStore *tree_model;
   GtkWidget *entry[20];
   GtkNotebook *notebook;
   struct gtk_s_helper *helper;
   char tmp_name[5], msg[1024];
   gboolean valid;

   helper = (struct gtk_s_helper *)userdata;
   notebook = GTK_NOTEBOOK(helper->notebook);
   tlv = 0;
   values = NULL;
   func = NULL;
   mode = 0;

   mode = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));

   /* Check if it is Yersinia log */
   if (mode == MAX_PROTOCOLS) {
      return TRUE;
   }

   params = protocols[mode].parameters;
   extra_params = protocols[mode].extra_parameters;

   if ((tree_model = GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(protocols_tree[mode])))) == NULL)
      write_log(0, "Error in gtk_tree_view_get_model\n");

   valid = gtk_tree_model_get_iter_first (GTK_TREE_MODEL(tree_model), &iter);

   for (i = 0; i < MAX_PACKET_STATS; i++)
   {
      if (protocols[mode].stats[i].header->ts.tv_sec > 0) 
      {
         /* If there isn't a row, append it */
         if (!valid) {
            gtk_list_store_append (GTK_LIST_STORE (tree_model), &iter);
         }

         if (protocols[mode].get_printable_packet)
         {
            if ((values = (*protocols[mode].get_printable_packet)(&protocols[mode].stats[i])) == NULL) 
            {
               write_log(0, "Error in get_printable_packet (mode %d)\n", mode);
               return FALSE;
            }
         }
         else
         {
            write_log(0, "Warning: there is no get_printable_packet for protocol %d\n", mode);
            return FALSE;
         }

         j = 0; k = 0;
         val = 0;
         gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, val, i, -1);
         val++;

         /* Normal parameters (-2 for the interface and defaults) */
         while (j < protocols[mode].nparams)
         {
            if (params[j].mwindow)
            {
               if (params[j].meaning)
               {
                  snprintf(meaningbuf, 64, "%s %s", values[k], parser_get_meaning(values[k], params[j].meaning));
                  gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, val, meaningbuf, -1);
               } else
                  gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, val, values[k], -1);

               val++;
            }
            if ((params[j].type != FIELD_IFACE) && (params[j].type != FIELD_DEFAULT) && (params[j].type != FIELD_EXTRA))
               k++;

            j++;
         }
         if ((protocols[mode].extra_nparams > 0))
         {
            tlv = k;
            j = 0;
            while(j < protocols[mode].extra_nparams)
            {
               if (extra_params[j].mwindow)
               {
                  ptrtlv = values[tlv];
                  while ((ptrtlv) && (strncmp((char *)ptrtlv, extra_params[j].ldesc, strlen(extra_params[j].ldesc)) != 0))
                  {
                     ptrtlv += strlen((char *)ptrtlv) + 1;
                  }

                  if (ptrtlv) 
                  {
                     ptrtlv += strlen((char *)ptrtlv) + 1;
                     if (extra_params[j].meaning)
                     {
                        snprintf(meaningbuf, 64, "%s %s", ptrtlv, parser_get_meaning(ptrtlv, extra_params[j].meaning));
                        gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, val, meaningbuf, -1);
                     } else
                        gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, val, ptrtlv, -1);
                     val++;
                  } else
                  {
                     gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, val, "???", -1);
                     val++;
                  }
               }
               j++;
            }
         }

         gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, val, protocols[mode].stats[i].iface, -1);
         val++;
         gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, val, protocols[mode].stats[i].total, -1);
         val++;
         strftime(timebuf, 19, "%d %b %H:%M:%S", localtime((time_t *)&protocols[mode].stats[i].header->ts));
         gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, val, timebuf, -1);

         k = 0;
         /* Reset values */
         //memset((void *)values, 0, sizeof(values));

         if (values) 
         {
            while(values[k]) 
            {
               free(values[k]);
               k++;
            }
            free(values);
         }

         valid = gtk_tree_model_iter_next (GTK_TREE_MODEL(tree_model), &iter);
      } /* if (protocols->tv_sec) */
   } /* for i < MAX_PACKET_STATS */

   /* Ok, now refresh the bwindow */
   if (!helper->edit_mode) {
      for (i = 0; i < protocols[mode].nparams; i++)
      {
         if ((params[i].type != FIELD_DEFAULT) && (params[i].type != FIELD_IFACE) && (params[i].type != FIELD_EXTRA))
         {
            snprintf(tmp_name, 5, "%02d%02d", mode, i);
            entry[i] = lookup_widget(GTK_WIDGET(notebook), tmp_name);
            parser_binary2printable(mode, i, helper->node->protocol[mode].commands_param[i], msg);
            gtk_entry_set_text(GTK_ENTRY(entry[i]), msg);
         }
      }
   }

   return TRUE;
}


void
gtk_c_tree_selection_changed_cb (GtkTreeSelection *selection, gpointer userdata)
{
   GtkTreeIter iter;
   GtkTreeModel *model;
   GtkWidget *tree;
   GtkListStore *tree_model;
   u_int8_t row;
   u_int8_t i, j, line, k, mode;
   char **values, *ptrtlv;
   struct commands_param *params;
   struct tuple_type_desc *func;
   struct gtk_s_helper *helper;

   helper = (struct gtk_s_helper *) userdata;
   values = NULL;
   func = NULL;
   row = 0;

   if (gtk_tree_selection_get_selected (selection, &model, &iter))
   {
      gtk_tree_model_get(model, &iter, 0, &row, -1);
   } else { /* TODO: get a proper selection */
      row = 0;
   }

   i = 0;
   line = 0;
   mode = gtk_notebook_get_current_page(GTK_NOTEBOOK(helper->notebook));
   params = (struct commands_param *)protocols[mode].parameters;

   if (protocols[mode].stats[row].header->ts.tv_sec <= 0) {
      write_log(0, "Ohhh no hay paquetes del modo %d, fila %d :(\n", mode, row);
      return;
   }

   tree = lookup_widget(GTK_WIDGET(helper->notebook), "main_vhvvs_tree");
   if ((tree_model = (GtkListStore *)gtk_tree_view_get_model(GTK_TREE_VIEW(tree))) == NULL)
      write_log(0, "Error in gtk_tree_view_get_model\n");

   gtk_list_store_clear(tree_model);

   if (protocols[mode].get_printable_packet) {
      if ((values = (*protocols[mode].get_printable_packet)(&protocols[mode].stats[row])) == NULL) {
         write_log(0, "Error in get_printable_packet (mode %d)\n", mode);
      }
   }
   else {
      write_log(0, "Warning: there is no get_printable_packet for protocol %d\n", mode);
   }

   j = 0;
   k = 0;

   /* Normal parameters (-2 for the interface and defaults) */
   while (j < protocols[mode].nparams)
   {
      if ((params[j].type != FIELD_IFACE) && (params[j].type != FIELD_DEFAULT) && (params[j].type != FIELD_EXTRA))
      {
         gtk_list_store_append(GTK_LIST_STORE(tree_model), &iter);
         gtk_list_store_set(GTK_LIST_STORE(tree_model), &iter, 0, params[j].ldesc, -1);
         gtk_list_store_set(GTK_LIST_STORE(tree_model), &iter, 1, values[k], -1);
         if (params[j].meaning)
            gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, 2, parser_get_meaning(values[k], params[j].meaning));
         k++;
      }
      j++;
   }

   ptrtlv = values[k];
   if (protocols[mode].extra_nparams > 0)
   {
      while ((ptrtlv) && (strlen((char *)ptrtlv) > 0))
      {
         gtk_list_store_append(GTK_LIST_STORE(tree_model), &iter);
         gtk_list_store_set(GTK_LIST_STORE(tree_model), &iter, 0, ptrtlv, -1);
         ptrtlv += strlen((char *)ptrtlv) + 1;
/*                     if (extra_params[j].meaning)
                     {
                        snprintf(meaningbuf, 64, "%s %s", ptrtlv, parser_get_meaning(ptrtlv, extra_params[j].meaning));
                        gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, val, meaningbuf, -1);
                     } else
                        gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, val, ptrtlv, -1);
                     val++;*/

         if (ptrtlv) 
         {
            gtk_list_store_set(GTK_LIST_STORE(tree_model), &iter, 1, ptrtlv, -1);
            ptrtlv += strlen((char *)ptrtlv) + 1;
         }
      }
   }

   gtk_list_store_append (GTK_LIST_STORE (tree_model), &iter);
   gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, 0, "Interface", -1); 
   gtk_list_store_set (GTK_LIST_STORE(tree_model), &iter, 1, protocols[mode].stats[row].iface, -1); 

   k = 0;
   if (values) 
   {
      while(values[k]) 
      {
         free((void *)values[k]);
         k++;
      }
      free(values);
   }
}


void
gtk_c_toggle_interface(GtkWidget *toggle, struct term_node *node)
{
   gboolean state;
   const gchar *label;
   dlist_t *found;
   struct interface_data *iface_data, *iface_new;

   label = gtk_button_get_label(GTK_BUTTON(toggle));


   state = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(toggle));
   if (!state) {
      found = dlist_search(node->used_ints->list, node->used_ints->cmp, (void *)label);
      iface_data = (struct interface_data *) dlist_data(found);
      interfaces_disable(iface_data->ifname);
      node->used_ints->list = dlist_remove(node->used_ints->list, (void *)iface_data);
   } else {
      /* First we need to get the interface index */
      found = dlist_search(interfaces->list, interfaces->cmp, (void *)label);

      if (!found) /* Not found */
         return;

      iface_data = (struct interface_data *) dlist_data(found);

      interfaces_enable(iface_data->ifname);
      iface_new = (struct interface_data *) calloc(1, sizeof(struct interface_data));
      memcpy((void *)iface_new, (void *)iface_data, sizeof(struct interface_data));
      node->used_ints->list = dlist_append(node->used_ints->list, (void *)iface_new);
   }
}

/*
gboolean
gtk_c_view_onPopupMenu(GtkWidget *treeview, gpointer userdata)
{
    view_popup_menu(treeview, NULL, userdata);

    return TRUE;
}*/


void
gtk_c_view_popup_menu(GtkWidget *menuitem, gpointer userdata)
{
    struct gtk_s_helper *helper;
    u_int8_t mode, row;
    struct term_node *node;

    helper = (struct gtk_s_helper *)userdata;

    node = (struct term_node *) helper->node;
    mode = helper->mode;
    row = helper->row;

    //write_log(0, "Cargando de mode es %d y row es %d\n", mode, row);
    if (protocols[mode].load_values)
        (*protocols[mode].load_values)((struct pcap_data *)&protocols[mode].stats[row], node->protocol[mode].tmp_data);
    else {
        write_log(0, "Warning: no load_values in protocol %d\n", mode);
    }
}


gboolean
gtk_c_view_onButtonPressed (GtkWidget *treeview, GdkEventButton *event, gpointer userdata)
{
    GtkWidget *notebook, *wmain;
    GtkTreeSelection *selection;
    GtkTreePath *path;
    struct gtk_s_helper *helper;
    gint *index;
    u_int8_t mode;


    index = NULL;
    notebook = lookup_widget(GTK_WIDGET(treeview), "main_vhv2_notebook");
    wmain = lookup_widget(GTK_WIDGET(treeview), "Main");
    mode = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));

    helper = (struct gtk_s_helper *) userdata;
    /* single click with the right mouse button? */
    if (event->type == GDK_BUTTON_PRESS  &&  event->button == 3)
    {
      selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));

     if (gtk_tree_selection_count_selected_rows(selection)  <= 1)
     {
           /* Get tree path for row that was clicked */
           if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(treeview),
                                             (gint) event->x, 
                                             (gint) event->y,
                                             &path, NULL, NULL, NULL))
           {
             index = gtk_tree_path_get_indices(path);
             gtk_tree_selection_unselect_all(selection);
             gtk_tree_selection_select_path(selection, path);
             gtk_tree_path_free(path);
           }
      }

     helper->mode = mode;
     helper->row = *index;
     gtk_i_view_menu(treeview, wmain, event, helper);

      return TRUE; /* we handled this */
    }

    return FALSE; /* we did not handle this */
}


void
gtk_c_on_extra_button_clicked(GtkButton *button, gpointer userdata)
{
   struct gtk_s_helper *helper;
   GtkWidget *extrawindow;

   helper = (struct gtk_s_helper *)userdata;

   //write_log(0, "helper es %d\n", helper->mode);
   extrawindow = gtk_i_create_extradialog(helper);
   gtk_widget_show(extrawindow);
}


void
gtk_c_extra_button_add_clicked(GtkButton *button, gpointer userdata)
{
   struct gtk_s_helper *helper;
   GtkWidget *window;
   u_int8_t proto;

   helper = (struct gtk_s_helper *)userdata;

   //write_log(0, "helper es %X\n", helper);
   proto = gtk_notebook_get_current_page(GTK_NOTEBOOK(helper->notebook));
   window = gtk_i_create_add_extradialog(helper, proto);
   gtk_widget_show(window);
}


void
gtk_c_add_extra_button_add_ok_clicked(GtkButton *button, gpointer userdata)
{
   struct gtk_s_helper *helper;

   helper = (struct gtk_s_helper *)userdata;
}
/* vim:set tabstop=3:set expandtab:set shiftwidth=3:set textwidth=78: */
