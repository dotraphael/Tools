using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using NotificationIcon.Properties;
using System.Xml;
using System.IO;
using System.Collections.Generic;
using System.Management.Automation;
using System.Collections.ObjectModel;
namespace NotificationIcon
{
	/// <summary>
	/// 
	/// </summary>
	class ProcessIcon : IDisposable
	{
		/// <summary>
		/// The NotifyIcon object.
		/// </summary>
		NotifyIcon objNotificationIcon;
    List<string> objIcons = new List<string>();
    string strFolder = AppDomain.CurrentDomain.BaseDirectory.ToString();

		/// <summary>
		/// Initializes a new instance of the <see cref="ProcessIcon"/> class.
		/// </summary>
		public ProcessIcon()
		{
			// Instantiate the NotifyIcon object.
      objNotificationIcon = new NotifyIcon();
		}

		/// <summary>
		/// Displays the icon in the system tray.
		/// </summary>
		public void Display()
		{
      ContextMenuStrip objMenu = new ContextMenuStrip();
      ToolStripMenuItem item;
      //string strFolder = AppDomain.CurrentDomain.BaseDirectory.ToString();

      if (!File.Exists((strFolder + "iconfile.xml")))
      {
        MessageBox.Show("File 'iconfile.xml' does not exist.", "NotificationIcon", MessageBoxButtons.OK, MessageBoxIcon.Error);
        Application.Exit();
      }
      else
      {
        XmlTextReader reader = new XmlTextReader(strFolder + "iconfile.xml");
        int i = 0;
        while (reader.Read())
        {
          if ((reader.NodeType == XmlNodeType.Element) && ((reader.Name.ToString().ToLower() == "default") || (reader.Name.ToString().ToLower() == "icon")))
          {
            item = new ToolStripMenuItem();
            item.Text = reader.GetAttribute("icontext").ToString();
            item.Name = i.ToString() + "-" + DateTime.Now.Millisecond.ToString();
            item.Tag = i;
            objIcons.Add(reader.GetAttribute("program").ToString() + "@" + reader.GetAttribute("params").ToString());
            item.Click += new EventHandler(itm_MouseClick);
            Icon iIco = new System.Drawing.Icon(strFolder + reader.GetAttribute("iconfile").ToString());
            item.Image = iIco.ToBitmap();

            if (reader.GetAttribute("bold").ToString().ToLower() == "true")
            {
              item.Font = new Font(item.Font.FontFamily, item.Font.Size, FontStyle.Bold);
              objNotificationIcon.Icon = iIco;
              objNotificationIcon.Text = item.Text;
            }
            objMenu.Items.Add(item);
            i++;
          }
        }
      }

      // Separator.
      objMenu.Items.Add(new ToolStripSeparator());

      // About.
      item = new ToolStripMenuItem();
      item.Text = "About";
      item.Click += new System.EventHandler(About_Click);
      objMenu.Items.Add(item);

      // Exit.
      item = new ToolStripMenuItem();
      item.Text = "Exit";
      item.Click += new System.EventHandler(Exit_Click);
      objMenu.Items.Add(item);

      objNotificationIcon.ContextMenuStrip = objMenu;
      objNotificationIcon.Visible = true;
    }

		/// <summary>
		/// Releases unmanaged and - optionally - managed resources
		/// </summary>
		public void Dispose()
		{
			// When the application closes, this will remove the icon from the system tray immediately.
      objNotificationIcon.Dispose();
		}

		/// <summary>
		/// Handles the MouseClick event of the ni control.
		/// </summary>
		/// <param name="sender">The source of the event.</param>
		/// <param name="e">The <see cref="System.Windows.Forms.MouseEventArgs"/> instance containing the event data.</param>
		void ni_MouseClick(object sender, MouseEventArgs e)
		{
      /*
			// Handle mouse button clicks.
			if (e.Button == MouseButtons.Left)
			{
        bool bIsDefaultOpen = false;
        foreach (Form form in Application.OpenForms)
        {
          if (form.GetType().ToString().ToLower() == "notificationicon." + gstrForm.ToLower())
          {
            bIsDefaultOpen = true;
            break;
          }
        }
        if (!bIsDefaultOpen)
        {
          bIsDefaultOpen = true;
          Type fForm = Type.GetType("NotificationIcon." + gstrForm);
          Form FAbout = (Form)Activator.CreateInstance(fForm);
          FAbout.Text = gstrIconText;
          if (gIco != null) { FAbout.Icon = gIco; }
          FAbout.ShowDialog();
          FAbout.Dispose();
          bIsDefaultOpen = false;
        }
      }
       * */
    }

    /// <summary>
    /// Handles the Click event of the Explorer control.
    /// </summary>
    /// <param name="sender">The source of the event.</param>
    /// <param name="e">The <see cref="System.EventArgs"/> instance containing the event data.</param>
    void itm_MouseClick(object sender, EventArgs e)
    {
      int Tag = (int)((ToolStripMenuItem)sender).Tag;
      string strProgram = objIcons[Tag].Split('@')[0];
      string strParams = objIcons[Tag].Split('@')[1];

      switch (strProgram.ToLower())
      {
        case "powershell.exe":
          if (!File.Exists(strParams))
          {
            MessageBox.Show("Powershell script '" + strParams + "' does not exist.", "NotificationIcon", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
          }
          using (PowerShell PowerShellInstance = PowerShell.Create())
          {
            string poshFile = string.Empty;
            poshFile = System.IO.File.ReadAllText(strParams);
            PowerShellInstance.AddScript(poshFile);

            PowerShellInstance.Invoke();
          }
          break;
        default:
          if (!File.Exists(strProgram))
          {
            MessageBox.Show("Executable file '" + strProgram + "' does not exist.", "NotificationIcon", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
          }

          ProcessStartInfo startInfo = new ProcessStartInfo();
          startInfo.CreateNoWindow = false;
          startInfo.UseShellExecute = false;
          startInfo.FileName = strProgram;
          startInfo.Arguments = strParams;

          try
          {
            // Start the process with the info we specified.
            // Call WaitForExit and then the using statement will close.
            using (Process exeProcess = Process.Start(startInfo))
            {
              exeProcess.WaitForExit();
            }
          }
          catch
          {
            // Log error.
          }
          break;
      }
    }

    /// <summary>
    /// Processes a menu item.
    /// </summary>
    /// <param name="sender">The sender.</param>
    /// <param name="e">The <see cref="System.EventArgs"/> instance containing the event data.</param>
    void About_Click(object sender, EventArgs e)
    {
      // Open About
      System.Diagnostics.Process.Start("http://www.rflsystems.co.uk");
    }

    /// <summary>
    /// Processes a menu item.
    /// </summary>
    /// <param name="sender">The sender.</param>
    /// <param name="e">The <see cref="System.EventArgs"/> instance containing the event data.</param>
    void Exit_Click(object sender, EventArgs e)
    {
      // Quit without further ado.
      Application.Exit();
    }
	}
}