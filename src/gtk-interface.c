/* gtk_interface.c
 *
 * GTK Interface setup
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
"$Id: gtk-interface.c 43 2007-04-27 11:07:17Z slay $";
#endif

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif


#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>

#include "gtk-interface.h"

#define GLADE_HOOKUP_OBJECT(component,widget,name) \
  g_object_set_data_full (G_OBJECT (component), name, \
    gtk_widget_ref (widget), (GDestroyNotify) gtk_widget_unref)

#define GLADE_HOOKUP_OBJECT_NO_REF(component,widget,name) \
  g_object_set_data (G_OBJECT (component), name, widget)

GtkWidget*
gtk_i_create_Main (struct gtk_s_helper *helper)
{
   u_int8_t i;
   char title[64];
   GtkWidget *Main;
   GtkWidget *main_vbox;
   GtkWidget *main_menubar;
   GtkWidget *menu_file;
   GtkWidget *menu_file_menu;
   GtkWidget *menu_file_open;
   GtkWidget *menu_file_save;
   GtkWidget *separatormenuitem1;
   GtkWidget *menu_file_quit;
   GtkWidget *menu_protocols;
   GtkWidget *menu_protocols_menu;
   GtkWidget *menu_protocols_proto1;
   GtkWidget *menu_actions;
   GtkWidget *menu_actions_menu;
   GtkWidget *menu_actions_execute;
   GtkWidget *menu_actions_execute_img;
   GtkWidget *menu_actions_interfaces;
   GtkWidget *menu_actions_interfaces_img;
   GtkWidget *menu_actions_load_default;
   GtkWidget *menu_actions_load_default_img;
   GtkWidget *menu_actions_list_attacks;
   GtkWidget *menu_actions_list_attacks_img;
   GtkWidget *menu_actions_clear;
   GtkWidget *menu_actions_clear_img;
   GtkWidget *menu_actions_clear_menu;
   GtkWidget *menu_clear_proto1;
   GtkWidget *menu_capture;
   GtkWidget *menu_capture_img;
   GtkWidget *menu_capture_menu;
   GtkWidget *menu_capture_proto1;
   GtkWidget *menu_options;
   GtkWidget *menu_options_menu;
   GtkWidget *menu_options_edit;
   GtkWidget *menu_options_macspoofing;
   GtkWidget *menu_help;
   GtkWidget *menu_help_menu;
   GtkWidget *menu_help_about;
   GtkWidget *toolbar;
   GtkIconSize tmp_toolbar_icon_size;
   GtkWidget *toolbar_launch_img;
   GtkWidget *toolbar_launch;
   GtkWidget *toolbar_interfaces_img;
   GtkWidget *toolbar_interfaces;
   GtkWidget *toolbar_default_img;
   GtkWidget *toolbar_default;
   GtkWidget *toolbar_list_attacks_img;
   GtkWidget *toolbar_list_attacks;
   GtkWidget *toolbar_clear;
   GtkWidget *toolbar_clear_img;
   GtkWidget *toolbar_capture;
   GtkWidget *toolbar_capture_img;
   GtkWidget *toolbar_edit;
   GtkWidget *toolbar_edit_img;
   GtkWidget *toolbar_quit_img;
   GtkWidget *toolbar_quit;
   GtkWidget *main_vbox_hpaned;
   GtkWidget *main_vh_vpaned;
   GtkWidget *main_vhv_scroll;
   GtkListStore *main_vhvs_tree_model;
   GtkListStore *main_vhvvs_tree_model;
   GtkTreeIter iter;
   GtkCellRenderer *cell;
   GtkCellRenderer *cell2;
   GtkTreeViewColumn *column;
   GtkWidget *main_vhvs_tree;
   GtkWidget *main_vhvvs_tree;
   GtkWidget *main_vhv_vbox;
   GtkWidget *main_vhvv_scroll;
   GtkWidget *main_vhvv_clock;
   GtkWidget *main_vhvv_eventbox;
   GtkWidget *main_vh2_vpaned;
   GtkTextBuffer *buffer_hex;
   GtkWidget *main_vhv2_scrollhex;
   GtkWidget *main_vhv2_texthex;
   GtkWidget *main_vhv2_notebook;
   GtkWidget *protocols_vpaned[MAX_PROTOCOLS + 1];
   GtkWidget *main_vhn_labels[MAX_PROTOCOLS + 1];
   GtkWidget *main_log_scroll;
   GtkWidget *main_log;
   GtkTooltips *tooltips;
   GtkAccelGroup *accel_group;
   GdkColor color;
   PangoFontDescription *font_desc;

   accel_group = gtk_accel_group_new ();

   /* Tooltips */
   tooltips = gtk_tooltips_new();
   helper->tooltips = tooltips;
   gtk_tooltips_enable(tooltips);

   /* Main window */
   Main = gtk_window_new (GTK_WINDOW_TOPLEVEL);
   snprintf(title, 64, "Yersinia %s", VERSION);
   gtk_window_set_title (GTK_WINDOW (Main), title);
   gtk_window_set_default_size (GTK_WINDOW (Main), 640, 480);

   main_vbox = gtk_vbox_new (FALSE, 0);
   gtk_widget_show (main_vbox);
   gtk_container_add (GTK_CONTAINER (Main), main_vbox);

   /* Menu widgets */
   main_menubar = gtk_menu_bar_new ();
   gtk_widget_show (main_menubar);
   gtk_box_pack_start (GTK_BOX (main_vbox), main_menubar, FALSE, FALSE, 0);

   /* Menu File */
   menu_file = gtk_menu_item_new_with_mnemonic (_("_File"));
   gtk_widget_show (menu_file);
   gtk_container_add (GTK_CONTAINER (main_menubar), menu_file);

   menu_file_menu = gtk_menu_new ();
   gtk_menu_item_set_submenu (GTK_MENU_ITEM (menu_file), menu_file_menu);

   /* Menu File - Open */
   menu_file_open = gtk_image_menu_item_new_from_stock ("gtk-open", accel_group);
   gtk_widget_show (menu_file_open);
   gtk_container_add (GTK_CONTAINER (menu_file_menu), menu_file_open);

   /* Menu File - Save */
   menu_file_save = gtk_image_menu_item_new_from_stock ("gtk-save", accel_group);
   gtk_widget_show (menu_file_save);
   gtk_container_add (GTK_CONTAINER (menu_file_menu), menu_file_save);

   /* Menu File - Separator */
   separatormenuitem1 = gtk_separator_menu_item_new ();
   gtk_widget_show (separatormenuitem1);
   gtk_container_add (GTK_CONTAINER (menu_file_menu), separatormenuitem1);
   gtk_widget_set_sensitive (separatormenuitem1, FALSE);

   /* Menu File - Quit */
   menu_file_quit = gtk_image_menu_item_new_from_stock ("gtk-quit", accel_group);
   gtk_widget_show (menu_file_quit);
   gtk_container_add (GTK_CONTAINER (menu_file_menu), menu_file_quit);

   /* Menu Protocols */
   menu_protocols = gtk_menu_item_new_with_mnemonic (_("_Protocols"));
   gtk_widget_show (menu_protocols);
   gtk_container_add (GTK_CONTAINER (main_menubar), menu_protocols);

   menu_protocols_menu = gtk_menu_new ();
   gtk_menu_item_set_submenu (GTK_MENU_ITEM (menu_protocols), menu_protocols_menu);

   /* Menu Protocols - PROTO_NAME */
   for (i = 0; i < MAX_PROTOCOLS; i++)
   {
      menu_protocols_proto1 = gtk_check_menu_item_new_with_mnemonic (_(protocols[i].namep));
      gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(menu_protocols_proto1), TRUE);

      if (protocols[i].visible)
         gtk_widget_show (menu_protocols_proto1);
      gtk_container_add (GTK_CONTAINER (menu_protocols_menu), menu_protocols_proto1);
      g_signal_connect ((gpointer) menu_protocols_proto1, "toggle",
            G_CALLBACK (gtk_c_on_protocols_toggle),
            &i);
   }

   /* Menu Actions */
   menu_actions = gtk_menu_item_new_with_mnemonic (_("_Actions"));
   gtk_widget_show (menu_actions);
   gtk_container_add (GTK_CONTAINER (main_menubar), menu_actions);

   menu_actions_menu = gtk_menu_new ();
   gtk_menu_item_set_submenu (GTK_MENU_ITEM (menu_actions), menu_actions_menu);

   /* Menu Actions - Execute Attack */
   menu_actions_execute = gtk_image_menu_item_new_with_mnemonic (_("e_Xecute attack"));
   menu_actions_execute_img = gtk_image_new_from_stock ("gtk-execute", GTK_ICON_SIZE_MENU);
   gtk_widget_show(menu_actions_execute_img);
   gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(menu_actions_execute), menu_actions_execute_img);
   gtk_widget_show (menu_actions_execute);
   gtk_container_add (GTK_CONTAINER (menu_actions_menu), menu_actions_execute);
   gtk_widget_add_accelerator (menu_actions_execute, "activate", accel_group,
         GDK_x, (GdkModifierType) GDK_CONTROL_MASK,
         GTK_ACCEL_VISIBLE);

   /* Menu Actions - Edit interfaces */
   menu_actions_interfaces = gtk_image_menu_item_new_with_mnemonic (_("edit _Interfaces"));
   menu_actions_interfaces_img = gtk_image_new_from_stock ("gtk-preferences", GTK_ICON_SIZE_MENU);
   gtk_widget_show(menu_actions_interfaces_img);
   gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(menu_actions_interfaces), menu_actions_interfaces_img);
   gtk_widget_show (menu_actions_interfaces);
   gtk_container_add (GTK_CONTAINER (menu_actions_menu), menu_actions_interfaces);
   gtk_widget_add_accelerator (menu_actions_interfaces, "activate", accel_group,
         GDK_i, (GdkModifierType) GDK_CONTROL_MASK,
         GTK_ACCEL_VISIBLE);

   /* Menu Actions - Load Default */
   menu_actions_load_default = gtk_image_menu_item_new_with_mnemonic (_("Load protocol _Default values"));
   menu_actions_load_default_img = gtk_image_new_from_stock ("gtk-network", GTK_ICON_SIZE_MENU);
   gtk_widget_show(menu_actions_load_default_img);
   gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(menu_actions_load_default), menu_actions_load_default_img);
   gtk_widget_show (menu_actions_load_default);
   gtk_container_add (GTK_CONTAINER (menu_actions_menu), menu_actions_load_default);
   gtk_widget_add_accelerator (menu_actions_load_default, "activate", accel_group,
         GDK_d, (GdkModifierType) GDK_CONTROL_MASK,
         GTK_ACCEL_VISIBLE);

   /* Menu Actions - List Attacks */
   menu_actions_list_attacks = gtk_image_menu_item_new_with_mnemonic (_("_list attacks"));
   menu_actions_list_attacks_img = gtk_image_new_from_stock ("gtk-justify-center", GTK_ICON_SIZE_MENU);
   gtk_widget_show(menu_actions_list_attacks_img);
   gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(menu_actions_list_attacks), menu_actions_list_attacks_img);
   gtk_widget_show (menu_actions_list_attacks);
   gtk_container_add (GTK_CONTAINER (menu_actions_menu), menu_actions_list_attacks);
   gtk_widget_add_accelerator (menu_actions_list_attacks, "activate", accel_group,
         GDK_T, (GdkModifierType) GDK_CONTROL_MASK,
         GTK_ACCEL_VISIBLE);

   /* Menu Actions - Clear stats */
   menu_actions_clear = gtk_image_menu_item_new_with_mnemonic (_("_Clear packet stats"));
   menu_actions_clear_img = gtk_image_new_from_stock ("gtk-clear", GTK_ICON_SIZE_MENU);
   gtk_widget_show(menu_actions_clear_img);
   gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(menu_actions_clear), menu_actions_clear_img);
   gtk_widget_show (menu_actions_clear);
   gtk_container_add (GTK_CONTAINER (menu_actions_menu), menu_actions_clear);

   menu_actions_clear_menu = gtk_menu_new();
   gtk_menu_item_set_submenu(GTK_MENU_ITEM(menu_actions_clear), menu_actions_clear_menu);

   /* Menu Actions - Clear stats - PROTO_NAME */
   for (i = 0; i < MAX_PROTOCOLS; i++)
   {
      menu_clear_proto1 = gtk_menu_item_new_with_mnemonic (_(protocols[i].namep));
      gtk_widget_set_name(menu_clear_proto1, protocols[i].namep);
      if (protocols[i].visible)
         gtk_widget_show (menu_clear_proto1);
      gtk_container_add (GTK_CONTAINER (menu_actions_clear_menu), menu_clear_proto1);
      g_signal_connect ((gpointer) menu_clear_proto1, "activate",
            G_CALLBACK (gtk_c_on_actions_clear_activate),
            helper);
   }

   /* Menu Actions - Clear stats - ALL PROTOCOLS */
   menu_clear_proto1 = gtk_menu_item_new_with_mnemonic (_("All protocols"));
   gtk_widget_set_name(menu_clear_proto1, "ALL");
   gtk_widget_show (menu_clear_proto1);
   gtk_container_add (GTK_CONTAINER (menu_actions_clear_menu), menu_clear_proto1);
   g_signal_connect ((gpointer) menu_clear_proto1, "activate",
         G_CALLBACK (gtk_c_on_actions_clear_activate),
         helper);

   /* Menu Actions - Capture Traffic */
   menu_capture = gtk_image_menu_item_new_with_mnemonic (_("Capture traffic"));
   menu_capture_img = gtk_image_new_from_stock("gtk-save", GTK_ICON_SIZE_MENU);
   gtk_widget_show(menu_capture_img);
   gtk_image_menu_item_set_image(GTK_IMAGE_MENU_ITEM(menu_capture), menu_capture_img);
   gtk_widget_show (menu_capture);
   gtk_container_add (GTK_CONTAINER (menu_actions_menu), menu_capture);

   menu_capture_menu = gtk_menu_new ();
   gtk_menu_item_set_submenu (GTK_MENU_ITEM (menu_capture), menu_capture_menu);

   /* Menu Actions - Capture Traffic - PROTO_NAME */
   for (i = 0; i < MAX_PROTOCOLS; i++)
   {
      menu_capture_proto1 = gtk_menu_item_new_with_mnemonic (_(protocols[i].namep));
      gtk_widget_set_name(menu_capture_proto1, protocols[i].namep);
      if (protocols[i].visible)
         gtk_widget_show (menu_capture_proto1);
      gtk_container_add (GTK_CONTAINER (menu_capture_menu), menu_capture_proto1);
      g_signal_connect ((gpointer) menu_capture_proto1, "activate",
            G_CALLBACK (gtk_c_on_capture_activate),
            helper);
   }

   /* Menu Actions - Capture Traffic - ALL PROTOCOLS */
   menu_capture_proto1 = gtk_menu_item_new_with_mnemonic (_("All protocols"));
   gtk_widget_set_name(menu_capture_proto1, "ALL");
   gtk_widget_show (menu_capture_proto1);
   gtk_container_add (GTK_CONTAINER (menu_capture_menu), menu_capture_proto1);
   g_signal_connect ((gpointer) menu_capture_proto1, "activate",
         G_CALLBACK (gtk_c_on_capture_activate),
         helper);

   /* Menu Options */
   menu_options = gtk_menu_item_new_with_mnemonic (_("_Options"));
   gtk_widget_show (menu_options);
   gtk_container_add (GTK_CONTAINER (main_menubar), menu_options);

   menu_options_menu = gtk_menu_new ();
   gtk_menu_item_set_submenu (GTK_MENU_ITEM (menu_options), menu_options_menu);

   /* Menu Options - Edit mode */
   /*menu_options_edit = gtk_check_menu_item_new_with_mnemonic (_("_Edit mode"));
     if (helper->edit_mode)
     gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(menu_options_edit), TRUE);
     else
     gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(menu_options_edit), FALSE);

     gtk_widget_show (menu_options_edit);
     gtk_container_add (GTK_CONTAINER (menu_options_menu), menu_options_edit);
     gtk_widget_add_accelerator (menu_options_edit, "activate", accel_group,
     GDK_E, (GdkModifierType) GDK_CONTROL_MASK,
     GTK_ACCEL_VISIBLE);*/

   /* Menu Options - MAC Spoofing */
   menu_options_macspoofing = gtk_check_menu_item_new_with_mnemonic (_("_MAC Spoofing"));
   if (helper->node->mac_spoofing)
      gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(menu_options_macspoofing), TRUE);
   else
      gtk_check_menu_item_set_active (GTK_CHECK_MENU_ITEM(menu_options_macspoofing), FALSE);

   gtk_widget_show (menu_options_macspoofing);
   gtk_container_add (GTK_CONTAINER (menu_options_menu), menu_options_macspoofing);
   gtk_widget_add_accelerator (menu_options_macspoofing, "activate", accel_group,
         GDK_M, (GdkModifierType) GDK_CONTROL_MASK,
         GTK_ACCEL_VISIBLE);

   /* Menu Help */
   menu_help = gtk_menu_item_new_with_mnemonic (_("_Help"));
   gtk_widget_show (menu_help);
   gtk_container_add (GTK_CONTAINER (main_menubar), menu_help);

   menu_help_menu = gtk_menu_new ();
   gtk_menu_item_set_submenu (GTK_MENU_ITEM (menu_help), menu_help_menu);

   /* Menu Help - About */
   menu_help_about = gtk_image_menu_item_new_from_stock ("gtk-about", accel_group);
   gtk_widget_show (menu_help_about);
   gtk_container_add (GTK_CONTAINER (menu_help_menu), menu_help_about);

   /* Toolbar */
   toolbar = gtk_toolbar_new();
   gtk_widget_show(toolbar);
   gtk_toolbar_set_style (GTK_TOOLBAR (toolbar), GTK_TOOLBAR_BOTH);
   gtk_toolbar_set_tooltips(GTK_TOOLBAR(toolbar), TRUE);
   gtk_box_pack_start (GTK_BOX (main_vbox), toolbar, FALSE, FALSE, 0);
   tmp_toolbar_icon_size = gtk_toolbar_get_icon_size (GTK_TOOLBAR (toolbar));

   /* Toolbar: launch attack */
   toolbar_launch_img = gtk_image_new_from_stock ("gtk-execute", tmp_toolbar_icon_size);
   gtk_widget_show (toolbar_launch_img);
   toolbar_launch = (GtkWidget*) gtk_tool_button_new (toolbar_launch_img, _("Launch attack"));
   gtk_tool_item_set_tooltip(GTK_TOOL_ITEM(toolbar_launch), tooltips, ("Launch a specific attack"), NULL);
   gtk_widget_show (toolbar_launch);
   gtk_container_add (GTK_CONTAINER (toolbar), toolbar_launch);

   /* Toolbar: edit interfaces */
   toolbar_interfaces_img = gtk_image_new_from_stock ("gtk-preferences", tmp_toolbar_icon_size);
   gtk_widget_show (toolbar_interfaces_img);
   toolbar_interfaces = (GtkWidget*) gtk_tool_button_new (toolbar_interfaces_img, _("Edit interfaces"));
   gtk_tool_item_set_tooltip(GTK_TOOL_ITEM(toolbar_interfaces), tooltips, ("Edit interfaces to sniff and inject data"), NULL);
   gtk_widget_show (toolbar_interfaces);
   gtk_container_add (GTK_CONTAINER (toolbar), toolbar_interfaces);

   /* Toolbar: load default values */
   toolbar_default_img = gtk_image_new_from_stock ("gtk-network", tmp_toolbar_icon_size);
   gtk_widget_show (toolbar_default_img);
   toolbar_default = (GtkWidget*) gtk_tool_button_new (toolbar_default_img, _("Load default"));
   gtk_tool_item_set_tooltip(GTK_TOOL_ITEM(toolbar_default), tooltips, ("Load protocol default (and random) values"), NULL);
   gtk_widget_show (toolbar_default);
   gtk_container_add (GTK_CONTAINER (toolbar), toolbar_default);

   /* Toolbar: list attacks */
   toolbar_list_attacks_img = gtk_image_new_from_stock ("gtk-justify-center", tmp_toolbar_icon_size);
   gtk_widget_show (toolbar_list_attacks_img);
   toolbar_list_attacks = (GtkWidget*) gtk_tool_button_new (toolbar_list_attacks_img, _("List attacks"));
   gtk_tool_item_set_tooltip(GTK_TOOL_ITEM(toolbar_list_attacks), tooltips, ("List running attacks (and kill them!)"), NULL);
   gtk_widget_show (toolbar_list_attacks);
   gtk_container_add (GTK_CONTAINER (toolbar), toolbar_list_attacks);

   /* Toolbar: clear */
   toolbar_clear_img = gtk_image_new_from_stock ("gtk-clear", tmp_toolbar_icon_size);
   gtk_widget_show (toolbar_clear_img);
   toolbar_clear = (GtkWidget*) gtk_menu_tool_button_new (toolbar_clear_img, _("Clear stats"));
   gtk_tool_item_set_tooltip(GTK_TOOL_ITEM(toolbar_clear), tooltips, ("Clear ALL packet statistics"), NULL);
   gtk_menu_tool_button_set_menu(GTK_MENU_TOOL_BUTTON(toolbar_clear), menu_actions_clear_menu);
   gtk_widget_show (toolbar_clear);
   gtk_container_add (GTK_CONTAINER (toolbar), toolbar_clear);

   /* Toolbar: capture */
   toolbar_capture_img = gtk_image_new_from_stock ("gtk-save", tmp_toolbar_icon_size);
   gtk_widget_show (toolbar_capture_img);
   toolbar_capture = (GtkWidget*) gtk_menu_tool_button_new (toolbar_capture_img, _("Capture"));
   gtk_tool_item_set_tooltip(GTK_TOOL_ITEM(toolbar_capture), tooltips, ("Capture traffic in PCAP format"), NULL);
   gtk_menu_tool_button_set_menu(GTK_MENU_TOOL_BUTTON(toolbar_capture), menu_capture_menu);
   gtk_widget_show (toolbar_capture);
   gtk_container_add (GTK_CONTAINER (toolbar), toolbar_capture);

   /* Toolbar: edit mode */
   toolbar_edit = (GtkWidget*) gtk_toggle_tool_button_new ();
   gtk_widget_show (toolbar_edit);
   gtk_tool_button_set_label (GTK_TOOL_BUTTON (toolbar_edit), _("Edit mode"));
   gtk_tool_item_set_tooltip(GTK_TOOL_ITEM(toolbar_edit), tooltips, ("Enable/Disable edit mode"), NULL);
   toolbar_edit_img = gtk_image_new_from_stock ("gtk-edit", tmp_toolbar_icon_size);
   gtk_widget_show (toolbar_edit_img);
   gtk_tool_button_set_icon_widget (GTK_TOOL_BUTTON (toolbar_edit), toolbar_edit_img);
   gtk_container_add (GTK_CONTAINER (toolbar), toolbar_edit);
   //gtk_toggle_tool_button_set_active (GTK_TOGGLE_TOOL_BUTTON (toggletoolbutton1), TRUE);

   /* Toolbar: quit */
   toolbar_quit_img = gtk_image_new_from_stock ("gtk-quit", tmp_toolbar_icon_size);
   gtk_widget_show (toolbar_quit_img);
   toolbar_quit = (GtkWidget*) gtk_tool_button_new (toolbar_quit_img, _("Exit"));
   gtk_tool_item_set_tooltip(GTK_TOOL_ITEM(toolbar_quit), tooltips, ("Quit: Bring da noize!!"), NULL);
   gtk_widget_show (toolbar_quit);
   gtk_container_add (GTK_CONTAINER (toolbar), toolbar_quit);

   main_vbox_hpaned = gtk_hpaned_new ();
   gtk_widget_show (main_vbox_hpaned);
   gtk_box_pack_start (GTK_BOX (main_vbox), main_vbox_hpaned, TRUE, TRUE, 0);

   main_vh_vpaned = gtk_vpaned_new ();
   gtk_widget_show (main_vh_vpaned);
   gtk_paned_pack1 (GTK_PANED (main_vbox_hpaned), main_vh_vpaned, FALSE, TRUE);

   main_vhv_scroll = gtk_scrolled_window_new (NULL, NULL);
   gtk_widget_set_size_request (main_vhv_scroll, 200, 250);
   gtk_widget_show (main_vhv_scroll);
   gtk_paned_pack1 (GTK_PANED (main_vh_vpaned), main_vhv_scroll, FALSE, TRUE);
   gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (main_vhv_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (main_vhv_scroll), GTK_SHADOW_IN);

   main_vhvs_tree = gtk_tree_view_new();
   gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(main_vhvs_tree), TRUE);
   main_vhvs_tree_model = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);

   gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW (main_vhv_scroll), main_vhvs_tree);
   gtk_tree_view_set_model (GTK_TREE_VIEW (main_vhvs_tree), GTK_TREE_MODEL (main_vhvs_tree_model));
   gtk_widget_show (main_vhvs_tree);

   for (i=0; i < MAX_PROTOCOLS; i++)
   {
      if (protocols[i].visible) {
         gtk_list_store_append (GTK_LIST_STORE (main_vhvs_tree_model), &iter);
         gtk_list_store_set (GTK_LIST_STORE(main_vhvs_tree_model), &iter, 0, protocols[i].namep, -1); 
         gtk_list_store_set (GTK_LIST_STORE(main_vhvs_tree_model), &iter, 1, protocols[i].packets, -1); 
      }
   }
   gtk_list_store_append (GTK_LIST_STORE (main_vhvs_tree_model), &iter);
   gtk_list_store_set (GTK_LIST_STORE(main_vhvs_tree_model), &iter, 0, "Total", -1);

   g_timeout_add(1000, (GSourceFunc)&gtk_c_tree_update, main_vhvs_tree_model);

   cell = gtk_cell_renderer_text_new ();
   cell2 = gtk_cell_renderer_text_new();

   column = gtk_tree_view_column_new_with_attributes ("Protocols", cell, "text", 0, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (main_vhvs_tree), GTK_TREE_VIEW_COLUMN (column));
   g_object_set(cell, "background", "Blue", "background-set", TRUE, NULL);
   g_object_set(cell, "foreground", "White", "foreground-set", TRUE, NULL);
   column = gtk_tree_view_column_new_with_attributes ("Packets", cell2, "text", 1, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (main_vhvs_tree), GTK_TREE_VIEW_COLUMN (column));

   main_vhv_vbox = gtk_vbox_new (FALSE, 5);
   gtk_widget_show (main_vhv_vbox);
   gtk_paned_pack2 (GTK_PANED (main_vh_vpaned), main_vhv_vbox, TRUE, TRUE);

   main_vhvv_scroll = gtk_scrolled_window_new (NULL, NULL);
   gtk_widget_show (main_vhvv_scroll);
   gtk_box_pack_start (GTK_BOX (main_vhv_vbox), main_vhvv_scroll, TRUE, TRUE, 0);
   gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (main_vhvv_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (main_vhvv_scroll), GTK_SHADOW_IN);

   main_vhvvs_tree = gtk_tree_view_new();
   gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(main_vhvvs_tree), TRUE);
   main_vhvvs_tree_model = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

   gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW (main_vhvv_scroll), main_vhvvs_tree);
   gtk_tree_view_set_model (GTK_TREE_VIEW (main_vhvvs_tree), GTK_TREE_MODEL (main_vhvvs_tree_model));
   gtk_widget_show (main_vhvvs_tree);

   cell = gtk_cell_renderer_text_new ();

   column = gtk_tree_view_column_new_with_attributes ("Field", cell, "text", 0, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (main_vhvvs_tree), GTK_TREE_VIEW_COLUMN (column));
   column = gtk_tree_view_column_new_with_attributes ("Value", cell, "text", 1, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (main_vhvvs_tree), GTK_TREE_VIEW_COLUMN (column));
   column = gtk_tree_view_column_new_with_attributes ("Description", cell, "text", 2, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (main_vhvvs_tree), GTK_TREE_VIEW_COLUMN (column));

   main_vhvv_eventbox = gtk_event_box_new();
   gtk_widget_set_size_request (main_vhvv_eventbox, 20, 20);
   color.red = 0;
   color.green = 0;
   color.blue = 0;
   //gtk_widget_modify_bg (GTK_WIDGET(main_vhvv_eventbox), GTK_STATE_NORMAL, &color);
   gtk_container_set_border_width(GTK_CONTAINER(main_vhvv_eventbox), 1);
   gtk_widget_show(main_vhvv_eventbox);
   main_vhvv_clock = gtk_label_new(_("00:00:00"));
   //gdk_color_parse ("green", &color);
   //gtk_widget_modify_fg (GTK_WIDGET(main_vhvv_clock), GTK_STATE_NORMAL, &color);
   gtk_widget_show(main_vhvv_clock);
   gtk_box_pack_start (GTK_BOX (main_vhv_vbox), main_vhvv_eventbox, FALSE, TRUE, 0);
   gtk_container_add(GTK_CONTAINER(main_vhvv_eventbox), main_vhvv_clock);

   main_vh2_vpaned = gtk_vpaned_new();
   gtk_widget_show(main_vh2_vpaned);
   gtk_paned_pack2 (GTK_PANED (main_vbox_hpaned), main_vh2_vpaned, TRUE, TRUE);

   main_vhv2_notebook = gtk_notebook_new ();
   gtk_widget_show (main_vhv2_notebook);
   helper->notebook = main_vhv2_notebook;
   gtk_paned_pack1 (GTK_PANED (main_vh2_vpaned), main_vhv2_notebook, TRUE, TRUE);

   GLADE_HOOKUP_OBJECT (Main, main_vhv2_notebook, "main_vhv2_notebook");
   for (i=0; i < MAX_PROTOCOLS; i++)
   {   
      protocols_vpaned[i] = create_protocol_mwindow(Main, helper, i);
      if (protocols[i].visible)
         gtk_widget_show(protocols_vpaned[i]);
      gtk_container_add (GTK_CONTAINER (main_vhv2_notebook), protocols_vpaned[i]);

      main_vhn_labels[i] = gtk_label_new (_(protocols[i].namep));

      if (protocols[i].visible)
         gtk_widget_show (main_vhn_labels[i]);
      gtk_notebook_set_tab_label (GTK_NOTEBOOK (main_vhv2_notebook), gtk_notebook_get_nth_page (GTK_NOTEBOOK (main_vhv2_notebook), i), main_vhn_labels[i]);
   }

   /* Yersinia log viewer */
   tty_tmp->buffer_log = gtk_text_buffer_new(NULL);

   main_log_scroll = gtk_scrolled_window_new(NULL, NULL);
   gtk_widget_show(main_log_scroll);
   gtk_container_add(GTK_CONTAINER(main_vhv2_notebook), main_log_scroll);
   gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (main_log_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (main_log_scroll), GTK_SHADOW_IN);

   main_log = gtk_text_view_new_with_buffer(tty_tmp->buffer_log);
   gtk_text_view_set_editable(GTK_TEXT_VIEW(main_log), FALSE);
   gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(main_log), FALSE);
   gtk_widget_show(main_log);
   gtk_container_add (GTK_CONTAINER (main_log_scroll), main_log);

   main_vhn_labels[MAX_PROTOCOLS] = gtk_label_new (_("Yersinia log"));
   gtk_widget_show(main_vhn_labels[MAX_PROTOCOLS]);
   gtk_tooltips_set_tip(tooltips, main_vhn_labels[MAX_PROTOCOLS], "Yersinia log for debugging purposes", NULL);
   gtk_notebook_set_tab_label (GTK_NOTEBOOK (main_vhv2_notebook), gtk_notebook_get_nth_page (GTK_NOTEBOOK (main_vhv2_notebook), MAX_PROTOCOLS), main_vhn_labels[MAX_PROTOCOLS]);

   /* Hexadecimal View */
   main_vhv2_scrollhex = gtk_scrolled_window_new (NULL, NULL);
   gtk_widget_show (main_vhv2_scrollhex);
   gtk_paned_pack2 (GTK_PANED (main_vh2_vpaned), main_vhv2_scrollhex, FALSE, TRUE);
   gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (main_vhv2_scrollhex), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (main_vhv2_scrollhex), GTK_SHADOW_IN);

   buffer_hex = gtk_text_buffer_new(NULL);

   main_vhv2_texthex = gtk_text_view_new_with_buffer(buffer_hex);
   /* We need to set a monospaced font for the alignment */
   font_desc = pango_font_description_from_string ("Monospace 10");
   gtk_widget_modify_font(main_vhv2_texthex, font_desc);
   //  pango_font_description_free(font_desc);
   gtk_widget_show (main_vhv2_texthex);
   gtk_container_add (GTK_CONTAINER (main_vhv2_scrollhex), main_vhv2_texthex);

   gtk_paned_pack2 (GTK_PANED (main_vh2_vpaned), main_vhv2_scrollhex, TRUE, TRUE);

   /* Status bar - botton of the screen */
   helper->statusbar = gtk_statusbar_new ();
   gtk_widget_show (helper->statusbar);

   gtk_box_pack_start (GTK_BOX (main_vbox), helper->statusbar, FALSE, FALSE, 0);

   helper->mode = gtk_notebook_get_current_page(GTK_NOTEBOOK(main_vhv2_notebook));

   /* Timeouts */
   g_timeout_add(500, (GSourceFunc)gtk_c_refresh_mwindow, (gpointer)helper);
   g_timeout_add(1000, (GSourceFunc)&gtk_c_clock_update, main_vhvv_clock);

   /* Menu signals */

   g_signal_connect ((gpointer) menu_file_open, "activate",
         G_CALLBACK (gtk_c_on_file_open_activate),
         helper);
   g_signal_connect ((gpointer) menu_file_save, "activate",
         G_CALLBACK (gtk_c_on_file_save_activate),
         helper);
   g_signal_connect ((gpointer) menu_file_quit, "activate",
         G_CALLBACK (gtk_c_on_file_quit_activate),
         helper);
   g_signal_connect ((gpointer) menu_protocols_proto1, "activate",
         G_CALLBACK (on_protocols_proto1_activate),
         NULL);
   g_signal_connect ((gpointer) menu_actions_execute, "activate",
         G_CALLBACK (gtk_c_on_actions_execute_activate),
         helper);
   g_signal_connect ((gpointer) menu_actions_interfaces, "activate",
         G_CALLBACK (gtk_c_on_actions_interfaces_activate),
         helper);
   g_signal_connect ((gpointer) menu_actions_load_default, "activate",
         G_CALLBACK (gtk_c_on_menu_actions_load_default_activate),
         helper);
   g_signal_connect ((gpointer) menu_actions_list_attacks, "activate",
         G_CALLBACK (gtk_c_on_menu_actions_list_attacks_activate),
         helper);
   g_signal_connect ((gpointer) menu_actions_clear, "activate",
         G_CALLBACK (on_menu_actions_clear_activate),
         main_vhv2_notebook);
   /*  g_signal_connect ((gpointer) menu_options_edit, "toggle",
       G_CALLBACK (gtk_c_on_menu_options_edit_toggle),
       helper);*/
   g_signal_connect ((gpointer) menu_options_macspoofing, "toggle",
         G_CALLBACK (on_menu_options_macspoofing_toggle),
         helper->node);
   g_signal_connect ((gpointer) menu_help_about, "activate",
         G_CALLBACK (on_help_about_activate),
         NULL);

   /* Toolbar signals */
   g_signal_connect ((gpointer) toolbar_launch, "clicked",
         G_CALLBACK (gtk_c_on_actions_execute_activate),
         helper);
   g_signal_connect ((gpointer) toolbar_interfaces, "clicked",
         G_CALLBACK (gtk_c_on_actions_interfaces_activate),
         helper);
   g_signal_connect ((gpointer) toolbar_default, "clicked",
         G_CALLBACK (gtk_c_on_menu_actions_load_default_activate),
         helper);
   g_signal_connect ((gpointer) toolbar_list_attacks, "clicked",
         G_CALLBACK (gtk_c_on_menu_actions_list_attacks_activate),
         helper);
   g_signal_connect ((gpointer) toolbar_clear, "clicked",
         G_CALLBACK (on_menu_actions_clear_activate),
         main_vhv2_notebook);
   g_signal_connect ((gpointer) toolbar_edit, "toggled",
         G_CALLBACK (gtk_c_on_menu_options_edit_toggle),
         helper);
   g_signal_connect ((gpointer) toolbar_quit, "clicked",
         G_CALLBACK (gtk_c_on_file_quit_activate),
         helper);

   /* Mwindow signals */
   g_signal_connect_after(G_OBJECT(main_vhv2_notebook), "switch-page",
         G_CALLBACK(gtk_c_refresh_mwindow_notebook), helper);

   /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (Main, Main, "Main");
   GLADE_HOOKUP_OBJECT (Main, main_vbox, "main_vbox");
   GLADE_HOOKUP_OBJECT (Main, main_menubar, "main_menubar");
   GLADE_HOOKUP_OBJECT (Main, menu_file, "menu_file");
   GLADE_HOOKUP_OBJECT (Main, menu_file_menu, "menu_file_menu");
   GLADE_HOOKUP_OBJECT (Main, menu_file_open, "menu_file_open");
   GLADE_HOOKUP_OBJECT (Main, menu_file_save, "menu_file_save");
   GLADE_HOOKUP_OBJECT (Main, separatormenuitem1, "separatormenuitem1");
   GLADE_HOOKUP_OBJECT (Main, menu_file_quit, "menu_file_quit");
   GLADE_HOOKUP_OBJECT (Main, menu_protocols, "menu_protocols");
   GLADE_HOOKUP_OBJECT (Main, menu_protocols_menu, "menu_protocols_menu");
   GLADE_HOOKUP_OBJECT (Main, menu_protocols_proto1, "menu_protocols_proto1");
   GLADE_HOOKUP_OBJECT (Main, menu_actions, "menu_actions");
   GLADE_HOOKUP_OBJECT (Main, menu_actions_menu, "menu_actions_menu");
   GLADE_HOOKUP_OBJECT (Main, menu_actions_execute, "menu_actions_execute");
   GLADE_HOOKUP_OBJECT (Main, menu_actions_interfaces, "menu_actions_interfaces");
   GLADE_HOOKUP_OBJECT (Main, menu_actions_load_default, "menu_actions_load_default");
   GLADE_HOOKUP_OBJECT (Main, menu_actions_list_attacks, "menu_actions_list_attacks");
   GLADE_HOOKUP_OBJECT (Main, menu_actions_clear, "menu_actions_clear");
   GLADE_HOOKUP_OBJECT (Main, menu_actions_clear_menu, "menu_actions_clear_menu");
   GLADE_HOOKUP_OBJECT (Main, menu_clear_proto1, "menu_clear_proto1");
   GLADE_HOOKUP_OBJECT (Main, menu_capture, "menu_capture");
   GLADE_HOOKUP_OBJECT (Main, menu_capture_menu, "menu_capture_menu");
   GLADE_HOOKUP_OBJECT (Main, menu_options, "menu_options");
   GLADE_HOOKUP_OBJECT (Main, menu_options_menu, "menu_options_menu");
   GLADE_HOOKUP_OBJECT (Main, menu_options_edit, "menu_options_edit");
   GLADE_HOOKUP_OBJECT (Main, menu_options_macspoofing, "menu_options_macspoofing");
   GLADE_HOOKUP_OBJECT (Main, menu_help, "menu_help");
   GLADE_HOOKUP_OBJECT (Main, menu_help_menu, "menu_help_menu");
   GLADE_HOOKUP_OBJECT (Main, menu_help_about, "menu_help_about");
   GLADE_HOOKUP_OBJECT (Main, toolbar_launch, "toolbar_launch");
   GLADE_HOOKUP_OBJECT (Main, toolbar_interfaces, "toolbar_interfaces");
   GLADE_HOOKUP_OBJECT (Main, toolbar_default, "toolbar_default");
   GLADE_HOOKUP_OBJECT (Main, toolbar_list_attacks, "toolbar_list_attacks");
   GLADE_HOOKUP_OBJECT (Main, toolbar_clear, "toolbar_clear");
   GLADE_HOOKUP_OBJECT (Main, toolbar_capture, "toolbar_capture");
   GLADE_HOOKUP_OBJECT (Main, toolbar_edit, "toolbar_edit");
   GLADE_HOOKUP_OBJECT (Main, toolbar_quit, "toolbar_quit");
   GLADE_HOOKUP_OBJECT (Main, main_vbox_hpaned, "main_vbox_hpaned");
   GLADE_HOOKUP_OBJECT (Main, main_vh_vpaned, "main_vh_vpaned");
   GLADE_HOOKUP_OBJECT (Main, main_vhv_scroll, "main_vhv_scroll");
   GLADE_HOOKUP_OBJECT (Main, main_vhvs_tree, "main_vhvs_tree");
   GLADE_HOOKUP_OBJECT (Main, main_vhv_vbox, "main_vhv_vbox");
   GLADE_HOOKUP_OBJECT (Main, main_vhvv_scroll, "main_vhvv_scroll");
   GLADE_HOOKUP_OBJECT (Main, main_vhvvs_tree, "main_vhvvs_tree");
   GLADE_HOOKUP_OBJECT (Main, main_vhv2_texthex, "main_vhv2_texthex");
   GLADE_HOOKUP_OBJECT (Main, main_vhvv_clock, "main_vhvv_clock");
   GLADE_HOOKUP_OBJECT (Main, helper->statusbar, "statusbar");

   gtk_window_add_accel_group (GTK_WINDOW (Main), accel_group);

   return Main;
}


GtkWidget*
gtk_i_create_opendialog (struct gtk_s_helper *helper)
{
   GtkWidget *opendialog;
   GtkWidget *opendialog_vbox;
   GtkWidget *opendialog_buttons;
   GtkWidget *opendialog_cancel_button;
   GtkWidget *opendialog_ok_button;

   opendialog = gtk_file_chooser_dialog_new (_("Open configuration file"), NULL, GTK_FILE_CHOOSER_ACTION_OPEN, NULL, NULL);
   GTK_WINDOW (opendialog)->type = GTK_WINDOW_TOPLEVEL;
   gtk_window_set_type_hint (GTK_WINDOW (opendialog), GDK_WINDOW_TYPE_HINT_DIALOG);

   opendialog_vbox = GTK_DIALOG (opendialog)->vbox;
   gtk_widget_show (opendialog_vbox);

   opendialog_buttons = GTK_DIALOG (opendialog)->action_area;
   gtk_widget_show (opendialog_buttons);
   gtk_button_box_set_layout (GTK_BUTTON_BOX (opendialog_buttons), GTK_BUTTONBOX_END);

   opendialog_cancel_button = gtk_button_new_from_stock ("gtk-cancel");
   gtk_widget_show (opendialog_cancel_button);
   gtk_dialog_add_action_widget (GTK_DIALOG (opendialog), opendialog_cancel_button, GTK_RESPONSE_CANCEL);
   GTK_WIDGET_SET_FLAGS (opendialog_cancel_button, GTK_CAN_DEFAULT);

   opendialog_ok_button = gtk_button_new_from_stock ("gtk-open");
   gtk_widget_show (opendialog_ok_button);
   gtk_dialog_add_action_widget (GTK_DIALOG (opendialog), opendialog_ok_button, GTK_RESPONSE_OK);
   GTK_WIDGET_SET_FLAGS (opendialog_ok_button, GTK_CAN_DEFAULT);

   g_signal_connect_swapped ((gpointer) opendialog_cancel_button, "clicked",
         G_CALLBACK (gtk_widget_destroy),
         GTK_OBJECT (opendialog));

   g_signal_connect ((gpointer) opendialog_ok_button, "clicked",
         G_CALLBACK (gtk_c_opendialog_open),
         helper);

   /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (opendialog, opendialog, "opendialog");
   GLADE_HOOKUP_OBJECT_NO_REF (opendialog, opendialog_vbox, "opendialog_vbox");
   GLADE_HOOKUP_OBJECT_NO_REF (opendialog, opendialog_buttons, "opendialog_buttons");
   GLADE_HOOKUP_OBJECT (opendialog, opendialog_cancel_button, "opendialog_cancel_button");
   GLADE_HOOKUP_OBJECT (opendialog, opendialog_ok_button, "opendialog_ok_button");

   gtk_widget_grab_default (opendialog_ok_button);
   return opendialog;
}


GtkWidget*
gtk_i_create_savedialog (struct gtk_s_helper *helper)
{
   GtkWidget *savedialog;
   GtkWidget *savedialog_vbox;
   GtkWidget *savedialog_buttons;
   GtkWidget *savedialog_cancel_button;
   GtkWidget *savedialog_ok_button;

   savedialog = gtk_file_chooser_dialog_new (_("Save config file"), NULL, GTK_FILE_CHOOSER_ACTION_SAVE, NULL, NULL);
   GTK_WINDOW (savedialog)->type = GTK_WINDOW_TOPLEVEL;
   gtk_window_set_type_hint (GTK_WINDOW (savedialog), GDK_WINDOW_TYPE_HINT_DIALOG);

   savedialog_vbox = GTK_DIALOG (savedialog)->vbox;
   gtk_widget_show (savedialog_vbox);

   savedialog_buttons = GTK_DIALOG (savedialog)->action_area;
   gtk_widget_show (savedialog_buttons);
   gtk_button_box_set_layout (GTK_BUTTON_BOX (savedialog_buttons), GTK_BUTTONBOX_END);

   savedialog_cancel_button = gtk_button_new_from_stock ("gtk-cancel");
   gtk_widget_show (savedialog_cancel_button);
   gtk_dialog_add_action_widget (GTK_DIALOG (savedialog), savedialog_cancel_button, GTK_RESPONSE_CANCEL);
   GTK_WIDGET_SET_FLAGS (savedialog_cancel_button, GTK_CAN_DEFAULT);

   savedialog_ok_button = gtk_button_new_from_stock ("gtk-open");
   gtk_widget_show (savedialog_ok_button);
   gtk_dialog_add_action_widget (GTK_DIALOG (savedialog), savedialog_ok_button, GTK_RESPONSE_OK);
   GTK_WIDGET_SET_FLAGS (savedialog_ok_button, GTK_CAN_DEFAULT);

   g_signal_connect_swapped ((gpointer) savedialog_cancel_button, "clicked",
         G_CALLBACK (gtk_widget_destroy),
         GTK_OBJECT (savedialog));

   g_signal_connect ((gpointer) savedialog_ok_button, "clicked",
         G_CALLBACK (gtk_c_savedialog_save),
         helper);

   /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (savedialog, savedialog, "savedialog");
   GLADE_HOOKUP_OBJECT_NO_REF (savedialog, savedialog_vbox, "savedialog_vbox");
   GLADE_HOOKUP_OBJECT_NO_REF (savedialog, savedialog_buttons, "savedialog_buttons");
   GLADE_HOOKUP_OBJECT (savedialog, savedialog_cancel_button, "savedialog_cancel_button");
   GLADE_HOOKUP_OBJECT (savedialog, savedialog_ok_button, "savedialog_ok_button");

   gtk_widget_grab_default (savedialog_ok_button);

   return savedialog;
}


GtkWidget*
gtk_i_create_capturedialog (struct gtk_s_helper *helper)
{
   GtkWidget *savedialog;
   GtkWidget *savedialog_vbox;
   GtkWidget *savedialog_buttons;
   GtkWidget *savedialog_cancel_button;
   GtkWidget *savedialog_ok_button;

   savedialog = gtk_file_chooser_dialog_new (_("Save capture file"), NULL, GTK_FILE_CHOOSER_ACTION_SAVE, NULL, NULL);
   GTK_WINDOW (savedialog)->type = GTK_WINDOW_TOPLEVEL;
   //gtk_window_set_type_hint (GTK_WINDOW (savedialog), GDK_WINDOW_TYPE_HINT_DIALOG);

   savedialog_vbox = GTK_DIALOG (savedialog)->vbox;
   gtk_widget_show (savedialog_vbox);

   savedialog_buttons = GTK_DIALOG (savedialog)->action_area;
   gtk_widget_show (savedialog_buttons);
   gtk_button_box_set_layout (GTK_BUTTON_BOX (savedialog_buttons), GTK_BUTTONBOX_END);

   savedialog_cancel_button = gtk_button_new_from_stock ("gtk-cancel");
   gtk_widget_show (savedialog_cancel_button);
   gtk_dialog_add_action_widget (GTK_DIALOG (savedialog), savedialog_cancel_button, GTK_RESPONSE_CANCEL);
   GTK_WIDGET_SET_FLAGS (savedialog_cancel_button, GTK_CAN_DEFAULT);

   savedialog_ok_button = gtk_button_new_from_stock ("gtk-open");
   gtk_widget_show (savedialog_ok_button);
   gtk_dialog_add_action_widget (GTK_DIALOG (savedialog), savedialog_ok_button, GTK_RESPONSE_OK);
   GTK_WIDGET_SET_FLAGS (savedialog_ok_button, GTK_CAN_DEFAULT);

   g_signal_connect_swapped ((gpointer) savedialog_cancel_button, "clicked",
         G_CALLBACK (gtk_widget_destroy),
         GTK_OBJECT (savedialog));

   g_signal_connect ((gpointer) savedialog_ok_button, "clicked",
         G_CALLBACK (gtk_c_capturedialog_save),
         helper);

   /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (savedialog, savedialog, "savedialog");
   GLADE_HOOKUP_OBJECT_NO_REF (savedialog, savedialog_vbox, "savedialog_vbox");
   GLADE_HOOKUP_OBJECT_NO_REF (savedialog, savedialog_buttons, "savedialog_buttons");
   GLADE_HOOKUP_OBJECT (savedialog, savedialog_cancel_button, "savedialog_cancel_button");
   GLADE_HOOKUP_OBJECT (savedialog, savedialog_ok_button, "savedialog_ok_button");

   gtk_widget_grab_default (savedialog_ok_button);

   return savedialog;
}


GtkWidget*
gtk_i_create_aboutdialog (void)
{
   GtkWidget *aboutdialog;
   int j;
   const gchar *authors[] = {
      "David Barroso Berrueta <tomac@yersinia.net>",
      "Alfredo Andr\303\251s Omella <slay@yersinia.net>",
      NULL
   };
   /* TRANSLATORS: Replace this string with your names, one name per line. */
   gchar *translators = _("translator-credits");
   GdkPixbuf *aboutdialog_logo_pixbuf;

   aboutdialog = gtk_about_dialog_new ();
   gtk_about_dialog_set_version (GTK_ABOUT_DIALOG (aboutdialog), VERSION);
   gtk_about_dialog_set_name (GTK_ABOUT_DIALOG (aboutdialog), _("Yersinia"));
   gtk_about_dialog_set_copyright (GTK_ABOUT_DIALOG (aboutdialog), _(" Yersinia\n By David Barroso <tomac@yersinia.net> and Alfredo Andres <slay@yersinia.net>\nCopyright 2005, 2006, 2007 Alfredo Andres and David Barroso"));
   j = term_motd();
   if (j >= 0)
      gtk_about_dialog_set_comments (GTK_ABOUT_DIALOG (aboutdialog), _(vty_motd[j]));

   gtk_about_dialog_set_license (GTK_ABOUT_DIALOG (aboutdialog), LICENSE); 
   gtk_about_dialog_set_website (GTK_ABOUT_DIALOG (aboutdialog), "http://www.yersinia.net");
   gtk_about_dialog_set_website_label (GTK_ABOUT_DIALOG (aboutdialog), _("http://daslfkjsdf"));
   gtk_about_dialog_set_authors (GTK_ABOUT_DIALOG (aboutdialog), authors);
   gtk_about_dialog_set_translator_credits (GTK_ABOUT_DIALOG (aboutdialog), translators);
   aboutdialog_logo_pixbuf = create_pixbuf ("yersinia.png");
   gtk_about_dialog_set_logo (GTK_ABOUT_DIALOG (aboutdialog), aboutdialog_logo_pixbuf);

   /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (aboutdialog, aboutdialog, "aboutdialog");

   return aboutdialog;
}


GtkWidget*
gtk_i_create_attacksdialog (GtkWidget *notebook, struct gtk_s_helper *helper, u_int8_t mode)
{
   GtkWidget *attacksdialog;
   GtkWidget *attacks_frame;
   GtkWidget *attacks_vbox;
   GtkWidget *attacks_v_table;
   GtkWidget *attacks_notebook;
   GtkWidget *attacks_n_labels[MAX_PROTOCOLS];
   GtkWidget *attacks_vt_radio_attack[MAX_PROTOCOLS];
   GtkWidget *attacks_vt_label_attack;
   GtkWidget *attacks_vt_label_dos;
   GtkWidget *attacks_vt_check_attack1;
   GtkWidget *attacks_v_hbox;
   GtkWidget *attacks_vh_cancel_button;
   GtkWidget *attacks_vh_ok_button;
   struct attack *theattack = NULL;
   u_int8_t i, j, num_attacks;

   attacksdialog = gtk_window_new (GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title (GTK_WINDOW (attacksdialog), _("Choose attack"));
   gtk_window_set_position (GTK_WINDOW (attacksdialog), GTK_WIN_POS_CENTER_ON_PARENT);

   attacks_vbox = gtk_vbox_new (FALSE, 0);
   gtk_widget_show (attacks_vbox);
   gtk_container_add (GTK_CONTAINER (attacksdialog), attacks_vbox);

   attacks_notebook = gtk_notebook_new ();
   gtk_widget_show(attacks_notebook);

   g_signal_connect_after(G_OBJECT(attacks_notebook), "switch-page",
         G_CALLBACK(gtk_c_attacks_synchro), (gpointer)notebook);

   gtk_box_pack_start (GTK_BOX (attacks_vbox), attacks_notebook, TRUE, TRUE, 0);

   for (i=0; i < MAX_PROTOCOLS; i++)
   {   
      if (protocols[i].attacks) {
         theattack = (struct attack *)protocols[i].attacks;

         attacks_frame = gtk_frame_new(_("Choose attack"));
         if (protocols[i].visible)
            gtk_widget_show(attacks_frame);
         gtk_container_add (GTK_CONTAINER (attacks_notebook), attacks_frame);

         attacks_n_labels[i] = gtk_label_new (_(protocols[i].namep));

         if (protocols[i].visible)
            gtk_widget_show (attacks_n_labels[i]);

         gtk_notebook_set_tab_label (GTK_NOTEBOOK (attacks_notebook), gtk_notebook_get_nth_page (GTK_NOTEBOOK (attacks_notebook), i), attacks_n_labels[i]);

         attacks_v_table = gtk_table_new (SIZE_ARRAY(theattack), 3, FALSE);
         gtk_widget_show (attacks_v_table);
         gtk_container_add(GTK_CONTAINER(attacks_frame), attacks_v_table);
         gtk_container_set_border_width (GTK_CONTAINER (attacks_v_table), 10);

         attacks_vt_label_attack = gtk_label_new (_("Description"));
         gtk_widget_show (attacks_vt_label_attack);
         gtk_table_attach (GTK_TABLE (attacks_v_table), attacks_vt_label_attack, 0, 1, 0, 1,
               (GtkAttachOptions) (GTK_FILL),
               (GtkAttachOptions) (0), 0, 0);
         gtk_misc_set_alignment (GTK_MISC (attacks_vt_label_attack), 0, 0.5);

         attacks_vt_label_dos = gtk_label_new (_("DoS"));
         gtk_widget_show (attacks_vt_label_dos);
         gtk_table_attach (GTK_TABLE (attacks_v_table), attacks_vt_label_dos, 1, 2, 0, 1,
               (GtkAttachOptions) (GTK_FILL),
               (GtkAttachOptions) (0), 0, 0);
         gtk_misc_set_alignment (GTK_MISC (attacks_vt_label_dos), 0, 0.5);

         num_attacks = 0;
         while(theattack[num_attacks].s)
            num_attacks++;

         for(j = 0; j < num_attacks; j++) {
            if (j == 0)
               attacks_vt_radio_attack[i] = gtk_radio_button_new_with_label(NULL, theattack[j].s);
            else
               attacks_vt_radio_attack[i] = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(attacks_vt_radio_attack[i]), (theattack[j].s));
            gtk_widget_show (attacks_vt_radio_attack[i]);

            g_signal_connect(attacks_vt_radio_attack[i], "toggled", (GCallback) gtk_c_attacks_radio_changed, helper);

            gtk_table_attach (GTK_TABLE (attacks_v_table), attacks_vt_radio_attack[i], 0, 1, j+1, j+2,
                  (GtkAttachOptions) (GTK_FILL),
                  (GtkAttachOptions) (0), 0, 0);

            attacks_vt_check_attack1 = gtk_check_button_new();
            gtk_widget_set_sensitive(GTK_WIDGET(attacks_vt_check_attack1), FALSE);
            if (theattack[j].type == DOS)
               gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(attacks_vt_check_attack1), TRUE);
            else
               gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(attacks_vt_check_attack1), FALSE);

            gtk_widget_show (attacks_vt_check_attack1);
            gtk_table_attach (GTK_TABLE (attacks_v_table), attacks_vt_check_attack1, 1, 2, j+1, j+2,
                  (GtkAttachOptions) (GTK_FILL),
                  (GtkAttachOptions) (0), 0, 0);
         }
      }
   }

   /* Start in the same label than the main window */
   gtk_notebook_set_current_page(GTK_NOTEBOOK(attacks_notebook), mode);

   attacks_v_hbox = gtk_hbox_new (TRUE, 0);
   gtk_widget_show (attacks_v_hbox);
   gtk_container_add (GTK_CONTAINER (attacks_vbox), attacks_v_hbox);

   attacks_vh_cancel_button = gtk_button_new_with_mnemonic (_("Cancel"));
   gtk_widget_show (attacks_vh_cancel_button);
   gtk_box_pack_start (GTK_BOX (attacks_v_hbox), attacks_vh_cancel_button, FALSE, TRUE, 0);

   g_signal_connect_swapped ((gpointer) attacks_vh_cancel_button, "clicked",
         G_CALLBACK (gtk_widget_destroy),
         GTK_OBJECT (attacksdialog));

   attacks_vh_ok_button = gtk_button_new_with_mnemonic (_("OK"));
   gtk_widget_show (attacks_vh_ok_button);
   gtk_box_pack_start (GTK_BOX (attacks_v_hbox), attacks_vh_ok_button, FALSE, TRUE, 0);

   g_signal_connect((gpointer) attacks_vh_ok_button, "clicked",
         G_CALLBACK (gtk_c_attacks_launch),
         helper);

   /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (attacksdialog, attacksdialog, "attacksdialog");
   GLADE_HOOKUP_OBJECT (attacksdialog, attacks_vbox, "attacks_vbox");
   GLADE_HOOKUP_OBJECT (attacksdialog, attacks_v_table, "attacks_v_table");
   GLADE_HOOKUP_OBJECT (attacksdialog, attacks_vt_label_attack, "attacks_vt_label_attack");
   GLADE_HOOKUP_OBJECT (attacksdialog, attacks_vt_label_dos, "attacks_vt_label_dos");
   GLADE_HOOKUP_OBJECT (attacksdialog, attacks_vt_check_attack1, "attacks_vt_check_attack1");
   GLADE_HOOKUP_OBJECT (attacksdialog, attacks_v_hbox, "attacks_v_hbox");
   GLADE_HOOKUP_OBJECT (attacksdialog, attacks_notebook, "attacks_notebook");
   GLADE_HOOKUP_OBJECT (attacksdialog, attacks_vh_cancel_button, "attacks_vh_cancel_button");
   GLADE_HOOKUP_OBJECT (attacksdialog, attacks_vh_ok_button, "attacks_vh_ok_button");

   return attacksdialog;
}


GtkWidget*
create_interfacesdialog (struct term_node *node)
{
   GtkWidget *interfacesdialog;
   GtkWidget *interfaces_frame;
   GtkWidget *interfaces_vbox;
   GtkWidget *interfaces_v_table;
   GtkWidget *interfaces_v_button;
   GtkWidget **int_checkb;
   dlist_t *p;
   struct interface_data *iface_data;
   u_int32_t i;
   void *found;

   interfacesdialog = gtk_window_new (GTK_WINDOW_TOPLEVEL);
   gtk_widget_set_size_request (interfacesdialog, 200, 150);
   gtk_window_set_title (GTK_WINDOW (interfacesdialog), _("Choose interfaces"));
   gtk_window_set_position (GTK_WINDOW (interfacesdialog), GTK_WIN_POS_CENTER_ON_PARENT);

   interfaces_frame = gtk_frame_new(_("Select interfaces"));
   gtk_widget_show(interfaces_frame);
   gtk_container_add(GTK_CONTAINER (interfacesdialog), interfaces_frame);

   interfaces_vbox = gtk_vbox_new (FALSE, 0);
   gtk_widget_show (interfaces_vbox);
   gtk_container_add (GTK_CONTAINER (interfaces_frame), interfaces_vbox);

   interfaces_v_table = gtk_table_new (dlist_length(interfaces->list), 1, FALSE);
   gtk_widget_show (interfaces_v_table);
   gtk_box_pack_start (GTK_BOX (interfaces_vbox), interfaces_v_table, TRUE, TRUE, 0);
   gtk_container_set_border_width (GTK_CONTAINER (interfaces_v_table), 5);

   int_checkb = (GtkWidget **) calloc(dlist_length(interfaces->list), sizeof(GtkWidget *));
   for (p = interfaces->list, i = 0; p; p = dlist_next(interfaces->list, p), i++) {
      iface_data = (struct interface_data *) dlist_data(p);
      found = dlist_search(node->used_ints->list, node->used_ints->cmp, (void *) iface_data->ifname);
      int_checkb[i] = gtk_check_button_new_with_mnemonic(iface_data->ifname);
      gtk_widget_show(int_checkb[i]);
      if (found)
         gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(int_checkb[i]), TRUE);
      else
         gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(int_checkb[i]), FALSE);
      gtk_table_attach (GTK_TABLE (interfaces_v_table), int_checkb[i], 0, 1, i, i + 1,
            (GtkAttachOptions) (GTK_FILL),
            (GtkAttachOptions) (0), 0, 0);

      g_signal_connect (int_checkb[i], "toggled", G_CALLBACK (gtk_c_toggle_interface), node);
   }

   interfaces_v_button = gtk_button_new_with_mnemonic (_("OK"));
   gtk_widget_show (interfaces_v_button);
   gtk_box_pack_start (GTK_BOX (interfaces_vbox), interfaces_v_button, FALSE, FALSE, 0);

   g_signal_connect_swapped ((gpointer) interfaces_v_button, "clicked",
         G_CALLBACK (gtk_widget_destroy),
         GTK_OBJECT (interfacesdialog));

   /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (interfacesdialog, interfacesdialog, "interfacesdialog");
   GLADE_HOOKUP_OBJECT (interfacesdialog, interfaces_vbox, "interfaces_vbox");
   GLADE_HOOKUP_OBJECT (interfacesdialog, interfaces_v_table, "interfaces_v_table");
   GLADE_HOOKUP_OBJECT (interfacesdialog, interfaces_v_button, "interfaces_v_button");

   return interfacesdialog;
}


GtkWidget*
gtk_i_create_listattacksdialog (struct term_node *node)
{
   GtkWidget *listattacksdialog;
   GtkWidget *listattacks_frame;
   GtkWidget *listattacks_vbox;
   GtkWidget *listattacks_v_hbox;
   GtkWidget *listattacks_vh_label;
   GtkWidget *listattacks_vh_labeln;
   GtkWidget *listattacks_vh_labeld;
   GtkWidget *listattacks_vh_button;
   GtkWidget *listattacks_v_cancel_button;
   GtkWidget *listattacks_v_ok_button;
   struct attack *theattack = NULL;
   u_int8_t i, j;

   listattacksdialog = gtk_window_new (GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title (GTK_WINDOW (listattacksdialog), _("Attacks list"));
   gtk_window_set_position (GTK_WINDOW (listattacksdialog), GTK_WIN_POS_CENTER_ON_PARENT);

   listattacks_frame = gtk_frame_new(_("Attacks list"));
   gtk_widget_show(listattacks_frame);
   gtk_container_add(GTK_CONTAINER (listattacksdialog), listattacks_frame);

   listattacks_vbox = gtk_vbox_new (FALSE, 0);
   gtk_widget_show (listattacks_vbox);
   gtk_container_add (GTK_CONTAINER (listattacks_frame), listattacks_vbox);

   for (i = 0; i < MAX_PROTOCOLS; i++)
   {
      theattack = protocols[i].attacks;
      for (j = 0; j < MAX_THREAD_ATTACK; j++)
      {
         if (node->protocol[i].attacks[j].up)
         {
            listattacks_v_hbox = gtk_hbox_new(FALSE, 0);
            gtk_widget_show(listattacks_v_hbox);

            listattacks_vh_label = gtk_label_new(protocols[i].namep);
            gtk_widget_show(listattacks_vh_label);
            gtk_box_pack_start(GTK_BOX(listattacks_v_hbox), listattacks_vh_label, TRUE, TRUE, 0);
            /*
               listattacks_vh_labeln = gtk_new_label(node->protocols[i].attacks[j].attack);
               gtk_widget_show(listattacks_vh_labeln):
               gtk_box_pack_start(GTK_BOX(listattacks_v_hbox), listattacks_vh_labeln, TRUE, TRUE, 0);
               */
            listattacks_vh_labeld = gtk_label_new(theattack[node->protocol[i].attacks[j].attack].s);
            gtk_widget_show(listattacks_vh_labeld);
            gtk_box_pack_start(GTK_BOX(listattacks_v_hbox), listattacks_vh_labeld, TRUE, TRUE, 0);

            listattacks_vh_button = gtk_button_new_with_label("Cancel attack");
            gtk_widget_show(listattacks_vh_button);
            gtk_box_pack_start(GTK_BOX(listattacks_v_hbox), listattacks_vh_button, TRUE, TRUE, 0);

            gtk_box_pack_start(GTK_BOX (listattacks_vbox), listattacks_v_hbox, TRUE, TRUE, 0);
         }
      }
   }

   listattacks_v_cancel_button = gtk_button_new_with_mnemonic (_("Cancel all attacks"));
   gtk_widget_show (listattacks_v_cancel_button);
   gtk_box_pack_start (GTK_BOX (listattacks_vbox), listattacks_v_cancel_button, FALSE, FALSE, 0);

   g_signal_connect ((gpointer) listattacks_v_cancel_button, "clicked",
         G_CALLBACK (gtk_c_listattacks_destroyall),
         node);

   listattacks_v_ok_button = gtk_button_new_with_mnemonic (_("Cancel"));
   gtk_widget_show (listattacks_v_ok_button);
   gtk_box_pack_start (GTK_BOX (listattacks_vbox), listattacks_v_ok_button, FALSE, FALSE, 0);

   g_signal_connect_swapped ((gpointer) listattacks_v_ok_button, "clicked",
         G_CALLBACK (gtk_widget_destroy),
         GTK_OBJECT (listattacksdialog));

   /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (listattacksdialog, listattacksdialog, "listattacksdialog");
   GLADE_HOOKUP_OBJECT (listattacksdialog, listattacks_vbox, "listattacks_vbox");
   GLADE_HOOKUP_OBJECT (listattacksdialog, listattacks_v_ok_button, "listattacks_v_ok_button");
   GLADE_HOOKUP_OBJECT (listattacksdialog, listattacks_v_cancel_button, "listattacks_v_cancel_button");

   return listattacksdialog;
}


GtkWidget*
gtk_i_create_warningdialog (char *msg, ...)
{
   GtkWidget *warningdialog;
   GtkWidget *warning_vbox;
   GtkWidget *warning_v_scroll;
   GtkWidget *warning_vs_text;
   GtkWidget *warning_v_button;
   va_list ap;
   char buffer[4096];

   va_start(ap, msg);
   vsnprintf(buffer, 4096, msg, ap);
   va_end(ap);

   warningdialog = gtk_window_new (GTK_WINDOW_POPUP);
   gtk_widget_set_size_request (warningdialog, 200, 150);
   gtk_window_set_title (GTK_WINDOW (warningdialog), _("Warning"));
   gtk_window_set_position (GTK_WINDOW (warningdialog), GTK_WIN_POS_CENTER_ON_PARENT);
   gtk_window_set_type_hint (GTK_WINDOW (warningdialog), GDK_WINDOW_TYPE_HINT_SPLASHSCREEN);

   warning_vbox = gtk_vbox_new (FALSE, 0);
   gtk_widget_show (warning_vbox);
   gtk_container_add (GTK_CONTAINER (warningdialog), warning_vbox);

   warning_v_scroll = gtk_scrolled_window_new (NULL, NULL);
   gtk_widget_show (warning_v_scroll);
   gtk_box_pack_start (GTK_BOX (warning_vbox), warning_v_scroll, TRUE, TRUE, 0);
   gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (warning_v_scroll), GTK_POLICY_NEVER, GTK_POLICY_NEVER);
   gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (warning_v_scroll), GTK_SHADOW_IN);

   warning_vs_text = gtk_text_view_new ();
   gtk_widget_show (warning_vs_text);
   gtk_container_add (GTK_CONTAINER (warning_v_scroll), warning_vs_text);
   gtk_text_view_set_editable (GTK_TEXT_VIEW (warning_vs_text), FALSE);
   gtk_text_view_set_wrap_mode (GTK_TEXT_VIEW (warning_vs_text), GTK_WRAP_WORD);
   gtk_text_view_set_cursor_visible (GTK_TEXT_VIEW (warning_vs_text), FALSE);
   gtk_text_buffer_set_text (gtk_text_view_get_buffer (GTK_TEXT_VIEW (warning_vs_text)), (buffer), -1);

   warning_v_button = gtk_button_new_with_mnemonic (_("OK"));
   gtk_widget_show (warning_v_button);
   gtk_box_pack_start (GTK_BOX (warning_vbox), warning_v_button, FALSE, FALSE, 0);

   g_signal_connect_swapped ((gpointer) warning_v_button, "clicked",
         G_CALLBACK (gtk_widget_destroy),
         GTK_OBJECT (warningdialog));

   /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (warningdialog, warningdialog, "warningdialog");
   GLADE_HOOKUP_OBJECT (warningdialog, warning_vbox, "warning_vbox");
   GLADE_HOOKUP_OBJECT (warningdialog, warning_v_scroll, "warning_v_scroll");
   GLADE_HOOKUP_OBJECT (warningdialog, warning_vs_text, "warning_vs_text");
   GLADE_HOOKUP_OBJECT (warningdialog, warning_v_button, "warning_v_button");

   return warningdialog;
}


GtkWidget*
gtk_i_create_extradialog (struct gtk_s_helper *helper)
{
   GtkWidget *extradialog;
   GtkWidget *extra_vbox;
   GtkWidget *extra_v_scroll;
   GtkWidget *extra_vs_text;
   GtkWidget *extra_v_button_add, *extra_v_button_remove, *extra_v_button_ok;

   extradialog = gtk_window_new (GTK_WINDOW_TOPLEVEL);
   gtk_widget_set_size_request (extradialog, 200, 150);
   gtk_window_set_title (GTK_WINDOW (extradialog), _("Extra parameters"));
   gtk_window_set_position (GTK_WINDOW (extradialog), GTK_WIN_POS_CENTER_ON_PARENT);
   gtk_window_set_type_hint (GTK_WINDOW (extradialog), GDK_WINDOW_TYPE_HINT_SPLASHSCREEN);

   extra_vbox = gtk_vbox_new (FALSE, 0);
   gtk_widget_show (extra_vbox);
   gtk_container_add (GTK_CONTAINER (extradialog), extra_vbox);

   extra_v_scroll = gtk_scrolled_window_new (NULL, NULL);
   gtk_widget_show (extra_v_scroll);
   gtk_box_pack_start (GTK_BOX (extra_vbox), extra_v_scroll, TRUE, TRUE, 0);
   gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (extra_v_scroll), GTK_POLICY_NEVER, GTK_POLICY_NEVER);
   gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (extra_v_scroll), GTK_SHADOW_IN);

   extra_vs_text = gtk_text_view_new ();
   gtk_widget_show (extra_vs_text);
   gtk_container_add (GTK_CONTAINER (extra_v_scroll), extra_vs_text);

   extra_v_button_add = gtk_button_new_with_mnemonic (_("Add"));
   gtk_widget_show (extra_v_button_add);
   gtk_box_pack_start (GTK_BOX (extra_vbox), extra_v_button_add, FALSE, FALSE, 0);

   extra_v_button_remove = gtk_button_new_with_mnemonic (_("Remove"));
   gtk_widget_show (extra_v_button_remove);
   gtk_box_pack_start (GTK_BOX (extra_vbox), extra_v_button_remove, FALSE, FALSE, 0);

   extra_v_button_ok = gtk_button_new_with_mnemonic (_("OK"));
   gtk_widget_show (extra_v_button_ok);
   gtk_box_pack_start (GTK_BOX (extra_vbox), extra_v_button_ok, FALSE, FALSE, 0);

   g_signal_connect ((gpointer) extra_v_button_add, "clicked",
         G_CALLBACK (gtk_c_extra_button_add_clicked),
         (gpointer) helper);

   g_signal_connect_swapped ((gpointer) extra_v_button_ok, "clicked",
         G_CALLBACK (gtk_widget_destroy),
         GTK_OBJECT (extradialog));

   /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (extradialog, extradialog, "extradialog");
   GLADE_HOOKUP_OBJECT (extradialog, extra_vbox, "extra_vbox");
   GLADE_HOOKUP_OBJECT (extradialog, extra_v_scroll, "extra_v_scroll");
   GLADE_HOOKUP_OBJECT (extradialog, extra_vs_text, "extra_vs_text");
   GLADE_HOOKUP_OBJECT (extradialog, extra_v_button_ok, "extra_v_button_ok");

   return extradialog;
}


GtkWidget*
gtk_i_create_add_extradialog (struct gtk_s_helper *helper, u_int8_t proto)
{
   GtkWidget *add_extradialog;
   GtkWidget *add_extra_vbox;
   GtkWidget *add_extra_v_table;
   GtkWidget *add_extra_v_lcombo, *add_extra_v_lentry;
   GtkWidget *add_extra_v_combo;
   GtkWidget *add_extra_v_entry;
   GtkWidget *add_extra_v_hbox;
   GtkWidget *add_extra_v_button_cancel, *add_extra_v_button_ok;
   struct commands_param_extra *params;
   u_int8_t i;

   add_extradialog = gtk_window_new (GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title (GTK_WINDOW (add_extradialog), _("Add add_extra parameter"));
   gtk_window_set_position (GTK_WINDOW (add_extradialog), GTK_WIN_POS_CENTER_ON_PARENT);
   gtk_window_set_type_hint (GTK_WINDOW (add_extradialog), GDK_WINDOW_TYPE_HINT_SPLASHSCREEN);

   add_extra_vbox = gtk_vbox_new (FALSE, 0);
   gtk_widget_show (add_extra_vbox);
   gtk_container_add (GTK_CONTAINER (add_extradialog), add_extra_vbox);

   add_extra_v_table = gtk_table_new(2, 2, TRUE);
   gtk_widget_show(add_extra_v_table);
   gtk_box_pack_start (GTK_BOX (add_extra_vbox), add_extra_v_table, FALSE, FALSE, 0);

   add_extra_v_lcombo = gtk_label_new("Choose type");
   gtk_widget_show(add_extra_v_lcombo);
   gtk_table_attach(GTK_TABLE(add_extra_v_table), add_extra_v_lcombo, 0, 1, 0, 1,
               (GtkAttachOptions) (GTK_FILL),
               (GtkAttachOptions) (0), 0, 0);

   add_extra_v_combo = gtk_combo_box_new_text();
   gtk_widget_show(add_extra_v_combo);
   gtk_table_attach(GTK_TABLE(add_extra_v_table), add_extra_v_combo, 1, 2, 0, 1,
               (GtkAttachOptions) (GTK_FILL),
               (GtkAttachOptions) (0), 0, 0);

   add_extra_v_lentry = gtk_label_new("Set value");
   gtk_widget_show(add_extra_v_lentry);
   gtk_table_attach(GTK_TABLE(add_extra_v_table), add_extra_v_lentry, 0, 1, 1, 2,
               (GtkAttachOptions) (GTK_FILL),
               (GtkAttachOptions) (0), 0, 0);

   add_extra_v_entry = gtk_entry_new();
   gtk_widget_show(add_extra_v_entry);
   gtk_table_attach(GTK_TABLE(add_extra_v_table), add_extra_v_entry, 1, 2, 1, 2,
               (GtkAttachOptions) (GTK_FILL),
               (GtkAttachOptions) (0), 0, 0);

   if (protocols[proto].extra_nparams > 0) {
      params = protocols[proto].extra_parameters;
      for (i = 0; i < protocols[proto].extra_nparams; i++) {
         gtk_combo_box_append_text(GTK_COMBO_BOX(add_extra_v_combo), params[i].desc);
      }
   }

   add_extra_v_hbox = gtk_hbox_new(FALSE, 0);
   gtk_widget_show(add_extra_v_hbox);
   gtk_container_add (GTK_CONTAINER (add_extra_vbox), add_extra_v_hbox);

   add_extra_v_button_cancel = gtk_button_new_with_mnemonic (_("Cancel"));
   gtk_widget_show (add_extra_v_button_cancel);
   gtk_box_pack_start (GTK_BOX (add_extra_v_hbox), add_extra_v_button_cancel, FALSE, TRUE, 0);

   add_extra_v_button_ok = gtk_button_new_with_mnemonic (_("OK"));
   gtk_widget_show (add_extra_v_button_ok);
   gtk_box_pack_start (GTK_BOX (add_extra_v_hbox), add_extra_v_button_ok, FALSE, TRUE, 0);

   g_signal_connect_swapped ((gpointer) add_extra_v_button_cancel, "clicked",
         G_CALLBACK (gtk_widget_destroy),
         GTK_OBJECT (add_extradialog));

   g_signal_connect ((gpointer) add_extra_v_button_ok, "clicked",
         G_CALLBACK (gtk_c_add_extra_button_add_ok_clicked),
         helper);

   /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (add_extradialog, add_extradialog, "add_extradialog");
   GLADE_HOOKUP_OBJECT (add_extradialog, add_extra_vbox, "add_extra_vbox");
   GLADE_HOOKUP_OBJECT (add_extradialog, add_extra_v_button_ok, "add_extra_v_button_ok");

   return add_extradialog;
}


GtkWidget*
gtk_i_create_attackparamsdialog (struct gtk_s_helper *helper, struct attack_param *param, u_int8_t nparams)
{
   GtkWidget *attackparamsdialog;
   GtkWidget *attackparams_frame;
   GtkWidget *attackparams_vbox;
   GtkWidget *attackparams_v_hbox;
   GtkWidget *attackparams_vh_label;
   GtkWidget **attackparams_vh_entry;
   GtkWidget *attackparams_vh_button;
   GtkWidget *attackparams_v_cancel_button;
   GtkWidget *attackparams_v_ok_button;
   u_int8_t i;
   char tmp_name[3];

   if ((attackparams_vh_entry = (GtkWidget **) calloc(nparams, sizeof(GtkWidget *))) == NULL) {
      write_log(0, "Error in calloc\n");
      return NULL;
   }

   attackparamsdialog = gtk_window_new(GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title (GTK_WINDOW (attackparamsdialog), _("Parameters list"));
   gtk_window_set_position (GTK_WINDOW (attackparamsdialog), GTK_WIN_POS_CENTER_ON_PARENT);

   attackparams_frame = gtk_frame_new(_("Parameters list"));
   gtk_widget_show(attackparams_frame);
   gtk_container_add(GTK_CONTAINER (attackparamsdialog), attackparams_frame);

   attackparams_vbox = gtk_vbox_new (FALSE, 0);
   gtk_widget_show (attackparams_vbox);
   gtk_container_add (GTK_CONTAINER (attackparams_frame), attackparams_vbox);

   for (i = 0; i < nparams; i++)
   {
      attackparams_v_hbox = gtk_hbox_new(FALSE, 0);
      gtk_widget_show(attackparams_v_hbox);
      attackparams_vh_label = gtk_label_new(_(param[i].desc));
      gtk_widget_show(attackparams_vh_label);
      attackparams_vh_entry[i] = gtk_entry_new();
      gtk_entry_set_editable(GTK_ENTRY(attackparams_vh_entry[i]), TRUE);
      gtk_entry_set_width_chars(GTK_ENTRY(attackparams_vh_entry[i]), param[i].size_print);
      gtk_entry_set_max_length(GTK_ENTRY(attackparams_vh_entry[i]), param[i].size_print);
      gtk_widget_show(attackparams_vh_entry[i]);

      gtk_box_pack_start(GTK_BOX(attackparams_v_hbox), attackparams_vh_label, TRUE, TRUE, 0);
      gtk_box_pack_start(GTK_BOX(attackparams_v_hbox), attackparams_vh_entry[i], TRUE, TRUE, 0);
      gtk_box_pack_start(GTK_BOX (attackparams_vbox), attackparams_v_hbox, TRUE, TRUE, 0);

      snprintf(tmp_name, 3, "%02d", i);
      GLADE_HOOKUP_OBJECT (attackparamsdialog, attackparams_vh_entry[i], tmp_name);
   }

   attackparams_vh_button = gtk_hbox_new(TRUE, 0);
   gtk_widget_show(attackparams_vh_button);
   gtk_container_add (GTK_CONTAINER (attackparams_vbox), attackparams_vh_button);

   attackparams_v_cancel_button = gtk_button_new_with_mnemonic (_("Cancel"));
   gtk_widget_show (attackparams_v_cancel_button);
   gtk_box_pack_start (GTK_BOX (attackparams_vh_button), attackparams_v_cancel_button, TRUE, FALSE, 0);

   attackparams_v_ok_button = gtk_button_new_with_mnemonic (_("OK"));
   gtk_widget_show (attackparams_v_ok_button);
   gtk_box_pack_start (GTK_BOX (attackparams_vh_button), attackparams_v_ok_button, TRUE, FALSE, 0);

   /* TODO: attack_free_param */
   g_signal_connect_swapped ((gpointer) attackparams_v_cancel_button, "clicked",
         G_CALLBACK (gtk_widget_destroy),
         GTK_OBJECT (attackparamsdialog));

   g_signal_connect((gpointer) attackparams_v_ok_button, "clicked",
         G_CALLBACK (gtk_c_attackparams_launch),
         helper);

   /* Store pointers to all widgets, for use by lookup_widget(). */
   GLADE_HOOKUP_OBJECT_NO_REF (attackparamsdialog, attackparamsdialog, "attackparamsdialog");
   GLADE_HOOKUP_OBJECT (attackparamsdialog, attackparams_vbox, "attackparams_vbox");
   GLADE_HOOKUP_OBJECT (attackparamsdialog, attackparams_v_ok_button, "attackparams_v_ok_button");
   GLADE_HOOKUP_OBJECT (attackparamsdialog, attackparams_v_cancel_button, "attackparams_v_cancel_button");

   return attackparamsdialog;
}


GtkWidget*
create_protocol_mwindow(GtkWidget *Main, struct gtk_s_helper *helper, u_int8_t proto)
{
   u_int8_t i, total, row;
   struct commands_param *params;
   struct commands_param_extra *extra_params;
   GtkWidget *vpaned, *fields_vbox, *fields_hbox[5], *field_label;
   GtkWidget *scroll, *vbox, *frame, *fixed;
   GtkWidget *entry[20], *extra_button;
   GtkCellRenderer *cell;
   GtkTreeViewColumn *column;
   GType *types;
   GtkTreeIter iter;
   PangoFontDescription *font_desc;
   char tmp_name[5], msg[1024];

   params = protocols[proto].parameters;
   extra_params = protocols[proto].extra_parameters;

   total = 0;

   for (i = 0; i < protocols[proto].nparams; i++) {
      if (params[i].mwindow)
         total++;
   }
   for (i = 0; i < protocols[proto].extra_nparams; i++) {
      if (extra_params[i].mwindow)
         total++;
   }

   vpaned = gtk_vpaned_new ();

   scroll = gtk_scrolled_window_new (NULL, NULL);
   gtk_widget_show (scroll);
   //    gtk_paned_pack1 (GTK_PANED (vpaned), scroll, TRUE, TRUE);
   gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (scroll), GTK_SHADOW_IN);

   protocols_tree[proto] = gtk_tree_view_new(); 
   gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(protocols_tree[proto]), TRUE);

   /* +4 for the index, interface, total count and the timestamp */
   types = g_new0 (GType, total + 4);

   types[0] = G_TYPE_INT;
   for (i = 1; i < total + 4; i++) {
      if (i == total + 4 - 2)
         types[i] = G_TYPE_ULONG;
      else
         types[i] = G_TYPE_STRING;
   }

   protocols_tree_model[proto] = gtk_list_store_newv(total + 4, types);
   g_free(types);

   gtk_widget_set_size_request (scroll, 250, 250);
   gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW (scroll), protocols_tree[proto]);
   gtk_tree_view_set_model (GTK_TREE_VIEW(protocols_tree[proto]), GTK_TREE_MODEL(protocols_tree_model[proto]));
   g_object_unref(protocols_tree_model[proto]);
   gtk_widget_show (protocols_tree[proto]);

   cell = gtk_cell_renderer_text_new ();

   total = 1;
   for (i = 0; i < protocols[proto].nparams; i++) {
      if (params[i].mwindow) {
         column = gtk_tree_view_column_new_with_attributes (params[i].ldesc, cell, "text", total, NULL);
         gtk_tree_view_append_column (GTK_TREE_VIEW (protocols_tree[proto]), GTK_TREE_VIEW_COLUMN (column));
         total++;
      }
   }

   for (i = 0; i < protocols[proto].extra_nparams; i++) {
      if (extra_params[i].mwindow) {
         column = gtk_tree_view_column_new_with_attributes (extra_params[i].ldesc, cell, "text", total, NULL);
         gtk_tree_view_append_column (GTK_TREE_VIEW (protocols_tree[proto]), GTK_TREE_VIEW_COLUMN (column));
         total++;
      }
   }

   column = gtk_tree_view_column_new_with_attributes ("Interface", cell, "text", total, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (protocols_tree[proto]), GTK_TREE_VIEW_COLUMN (column));
   total++;
   column = gtk_tree_view_column_new_with_attributes ("Count", cell, "text", total, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (protocols_tree[proto]), GTK_TREE_VIEW_COLUMN (column));
   total++;
   column = gtk_tree_view_column_new_with_attributes ("Last seen", cell, "text", total, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW (protocols_tree[proto]), GTK_TREE_VIEW_COLUMN (column));

   /* Setup the click handler */
   g_signal_connect(protocols_tree[proto], "button-press-event", (GCallback) gtk_c_view_onButtonPressed, helper);
   //	g_signal_connect(protocols_tree[proto], "popup-menu", (GCallback) gtk_c_view_onPopupMenu, NULL);

   /* Setup the selection handler */

   helper->select = gtk_tree_view_get_selection (GTK_TREE_VIEW (protocols_tree[proto]));
   gtk_tree_selection_set_mode (helper->select, GTK_SELECTION_SINGLE);
   /* Update the packet information in the left widget */
   g_signal_connect (G_OBJECT (helper->select), "changed",
         G_CALLBACK (gtk_c_tree_selection_changed_cb), helper);

   /* Update the hexview */
   g_signal_connect (G_OBJECT (helper->select), "changed",
         G_CALLBACK (gtk_c_update_hexview), helper);

/*   for (i = 0; i < MAX_PACKET_STATS; i++) {
      gtk_list_store_append (GTK_LIST_STORE (protocols_tree_model[proto]), &iter);
      gtk_list_store_set (GTK_LIST_STORE(protocols_tree_model[proto]), &iter, 0, i, -1);
   }*/

   vbox = gtk_vbox_new (FALSE, 0);
   gtk_widget_show (vbox);
   gtk_paned_pack1 (GTK_PANED (vpaned), vbox, FALSE, TRUE);

   /* A frame which name is the protocol name */
   frame = gtk_frame_new(protocols[proto].description);
   gtk_widget_show(frame);

   /* Ncurses compability: we are going to have 5 rows and in each row, 2*number of fields */
   fixed = gtk_fixed_new ();
   gtk_widget_set_size_request (fixed, 200, 200);
   gtk_widget_show (fixed);
   gtk_box_pack_start (GTK_BOX (vbox), scroll, TRUE, TRUE, 0);
   gtk_box_pack_start (GTK_BOX (vbox), frame, TRUE, TRUE, 0);

   fields_vbox = gtk_vbox_new(FALSE, 0);
   gtk_widget_show(fields_vbox);
   gtk_container_add(GTK_CONTAINER(frame), fields_vbox);

   for (i = 0; i < 5; i++) {
      fields_hbox[i] = gtk_hbox_new(FALSE, 25);
      gtk_widget_show(fields_hbox[i]);
      gtk_box_pack_start(GTK_BOX(fields_vbox), fields_hbox[i], TRUE, TRUE, 0);
   }

   for (i = 0; i < protocols[proto].nparams; i++) {
      if ((params[i].type != FIELD_DEFAULT) && (params[i].type != FIELD_IFACE) && (params[i].type != FIELD_EXTRA)) {
         field_label = gtk_label_new(params[i].ldesc); 
         gtk_widget_show(field_label);
         entry[i] = gtk_entry_new();
         gtk_entry_set_width_chars(GTK_ENTRY(entry[i]), params[i].size_print);
         /* By default, entry widgets are not editable, you have to turn on
          * edit mode */
         gtk_entry_set_editable(GTK_ENTRY(entry[i]), FALSE);

         /* Set up a monospaced font */
         font_desc = pango_font_description_from_string ("Monospace 10");
         gtk_widget_modify_font(entry[i], font_desc);
         gtk_widget_show(entry[i]);

         /* Initialize the values */
         parser_binary2printable(proto, i, helper->node->protocol[proto].commands_param[i], msg);
         gtk_entry_set_text(GTK_ENTRY(entry[i]), msg);

         row = params[i].row;
         gtk_box_pack_start(GTK_BOX(fields_hbox[row-1]), field_label, FALSE, TRUE, 0);
         gtk_box_pack_start(GTK_BOX(fields_hbox[row-1]), entry[i], FALSE, TRUE, 0);

         /* We are going to refer to the entry boxes as XXYY where XX is the protocol number, and YY the field number */
         snprintf(tmp_name, 5, "%02d%02d", proto, i);
         GLADE_HOOKUP_OBJECT (Main, entry[i], tmp_name);
      } 
   }

   if (protocols[proto].extra_nparams > 0)
   {
      extra_button = gtk_button_new_with_label("Extra");
      gtk_widget_show(extra_button);
      gtk_box_pack_start(GTK_BOX(fields_hbox[0]), extra_button, FALSE, TRUE, 0);
      g_signal_connect ((gpointer) extra_button, "clicked",
            G_CALLBACK (gtk_c_on_extra_button_clicked),
            helper);
   }

   /* Store pointers to all widgets, for use by lookup_widget(). */
   return vpaned;
}


void
gtk_i_view_menu(GtkWidget *treeview, GtkWidget *wmain, GdkEventButton *event, struct gtk_s_helper *helper)
{
   GtkWidget *menu, *menuitem;

   menu = gtk_menu_new();

   menuitem = gtk_menu_item_new_with_label(_("Learn packet from network"));

   g_signal_connect(menuitem, "activate",
         (GCallback) gtk_c_view_popup_menu, helper);

   gtk_menu_shell_append(GTK_MENU_SHELL(menu), menuitem);

   gtk_widget_show_all(menu);

   /* Note: event can be NULL here when called from view_onPopupMenu;
    *  gdk_event_get_time() accepts a NULL argument */
   gtk_menu_popup(GTK_MENU(menu), NULL, NULL, NULL, NULL,
         (event != NULL) ? event->button : 0,
         gdk_event_get_time((GdkEvent*)event));

   GLADE_HOOKUP_OBJECT (wmain, menuitem, "menuitem");
}

/* vim:set tabstop=4:set expandtab:set shiftwidth=4:set textwidth=78: */
