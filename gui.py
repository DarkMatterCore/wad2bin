# By LyfeOnEdge
import os, sys, platform, subprocess, threading
import tkinter as tk
import tkinter.filedialog as tkfiledialog
from tkinter.ttk import LabelFrame, Notebook

# Get OS information.
g_osType = platform.system()
g_osVersion = platform.version()

# Get Windows information.
g_isWindowsVista = False
if g_osType == 'Windows': g_isWindowsVista = int(g_osVersion.split('.')[0]) >= 6

class Style:
    def __init__(self):
        self.WINDOWS_SCALING_FACTOR = 96.0
        self.SCALE = 1.0

        self.STANDARD_OFFSET = 10 #Offset to place everything
        self.BUTTONSIZE = 30

        self.monospace = ("Monospace",10,"normal")
        self.boldmonospace = ("Monospace",10,"bold")
        self.BUTTON_FONT = self.monospace

        self.BACKGROUND_COLOR = "#20232a"
        self.BUTTON_COLOR = "#aaaaaa"
        self.ENTRY_COLOR = "#373940"
        self.ENTRY_FOREGROUND = "#bbbbbb"
        self.LABEL_COLOR = "#61dafb"

        # Enable high DPI scaling under Windows (if possible).
        self.dpi_aware = False
        if g_isWindowsVista:
            try:
                import ctypes
                self.dpi_aware = (ctypes.windll.user32.SetProcessDPIAware() == 1)
                if not self.dpi_aware: self.dpi_aware = (ctypes.windll.shcore.SetProcessDpiAwareness(1) == 0)
            except:
                traceback.print_exc()

        # Create temporary Tk object.
        root = tk.Tk()

        # Get screen resolution.
        self.screen_width_px = root.winfo_screenwidth()
        self.screen_height_px = root.winfo_screenheight()

        # Get pixel density (DPI).
        self.screen_dpi = round(root.winfo_fpixels('1i'))

        # Destroy temporary Tk object.
        root.destroy()

        # Update scaling factor (if needed).
        if self.dpi_aware:
            self.SCALE = (float(self.screen_dpi) / self.WINDOWS_SCALING_FACTOR)
            self.STANDARD_OFFSET = self.scale_measure(self.STANDARD_OFFSET)
            self.BUTTONSIZE = self.scale_measure(self.BUTTONSIZE)

    def scale_measure(self, measure):
        return round(float(measure) * self.SCALE)

style = Style()

class themedFrame(tk.Frame):
    def __init__(self, frame, **kw):
        tk.Frame.__init__(self, frame, **kw)
        if not (kw.get("background") or kw.get("bg")):
            self.configure(bg=style.BACKGROUND_COLOR)
        if not kw.get("borderwidth"):
            self.configure(borderwidth=0)
        if not kw.get("highlightthickness"):
            self.configure(highlightthickness=0)

class Button(tk.Label):
    """Cross-platform button"""
    def __init__(self, frame, callback, **kw):
        self.callback = callback
        self.background = "#aaaaaa"
        self.selected = False
        tk.Label.__init__(self, frame, **kw)
        self.configure(anchor="center")
        self.configure(background=self.background)
        self.configure(highlightthickness=1)
        if not "font" in kw.keys():
            self.configure(font=style.BUTTON_FONT)
        self.configure(highlightbackground="#999999")
        self.bind('<Button-1>', self.on_click)

    # Use callback when our makeshift "button" clicked
    def on_click(self, event=None):
        self.configure(background="#dddddd")
        if not self.selected:
            self.after(100, self.on_click_color_change)
        if self.callback:
            self.callback()

    # Function to set the button's image
    def setimage(self, image):
        self.configure(image=image)

    # Function to set the button's text
    def settext(self, text):
        self.configure(text=text)

    def deselect(self):
        self.selected = False
        self.configure(background=self.background)

    def on_click_color_change(self):
        if not self.selected:
            self.configure(background=self.background)


class PathEntry(tk.Entry):
    """Tkinter entry widget with a button to set the file path using tkinter's file dialog"""
    def __init__(self, frame, dir=False, filetypes=None, *args, **kw):
        self.dir = dir
        self.filetypes = filetypes
        container = themedFrame(frame)
        self.button = Button(container, self.set_path, text="...")
        self.button.place(relheight=1, relx=1, x=- style.BUTTONSIZE, width=style.BUTTONSIZE)
        tk.Entry.__init__(self, container, *args, **kw)
        self.text_var = tk.StringVar()
        self.configure(textvariable=self.text_var)
        self.configure(background=style.ENTRY_COLOR)
        self.configure(foreground=style.ENTRY_FOREGROUND)
        self.configure(borderwidth=0)
        self.configure(highlightthickness=2)
        self.configure(highlightbackground=style.BUTTON_COLOR)
        super().place(relwidth=1, relheight=1, width=- style.BUTTONSIZE)
        self.container = container

    def clear(self):
        self.text_var.set("")

    def set(self, string):
        self.text_var.set(string)

    def get_var(self):
        return self.text_var

    def get(self):
        return self.text_var.get()

    def place(self, **kw):
        self.container.place(**kw)

    def set_path(self):
        if not self.dir:
            self.set(tkfiledialog.askopenfilename(filetypes=self.filetypes))
        else:
            self.set(tkfiledialog.askdirectory())

class LabeledPathEntry(PathEntry):
    """Gives the PathEntry class a label"""
    def __init__(self, frame, text, *args, **kw):
        self.xtainer = themedFrame(frame)
        label = tk.Label(self.xtainer, text=text, background=style.BACKGROUND_COLOR, foreground=style.LABEL_COLOR)
        label.place(width=label.winfo_reqwidth(), relheight=1)
        PathEntry.__init__(self, self.xtainer, *args, **kw)
        PathEntry.place(self, relwidth=1, relheight=1, width=- (label.winfo_reqwidth() + style.scale_measure(5)), x=label.winfo_reqwidth() + style.scale_measure(5))

    def place(self, **kw):
        self.xtainer.place(**kw)

class LabeledEntry(tk.Entry):
    """Tkinter entry widget with a button to set the file path using tkinter's file dialog"""
    def __init__(self, frame, text, *args, **kw):
        self.container = themedFrame(frame)
        label = tk.Label(self.container, text=text, background=style.BACKGROUND_COLOR, foreground=style.LABEL_COLOR)
        label.place(width=label.winfo_reqwidth(), relheight=1)
        tk.Entry.__init__(self, self.container, *args, **kw)
        tk.Entry.place(self, relwidth=1, relheight=1, width=- (label.winfo_reqwidth() + style.scale_measure(5)), x=label.winfo_reqwidth() + style.scale_measure(5))
        self.text_var = tk.StringVar()
        self.configure(textvariable=self.text_var)
        self.configure(background=style.ENTRY_COLOR)
        self.configure(foreground=style.ENTRY_FOREGROUND)
        self.configure(borderwidth=0)
        self.configure(highlightthickness=2)
        self.configure(highlightbackground=style.BUTTON_COLOR)

    def clear(self):
        self.text_var.set("")

    def set(self, string):
        self.text_var.set(string)

    def get_var(self):
        return self.text_var

    def get(self):
        return self.text_var.get()

    def place(self, **kw):
        self.container.place(**kw)


class AutoScroll(object):
    def __init__(self, master):
        try:
            vsb = tk.Scrollbar(master, orient='vertical', command=self.yview)
        except:
            pass
        hsb = tk.Scrollbar(master, orient='horizontal', command=self.xview)

        try:
            self.configure(yscrollcommand=self._autoscroll(vsb))
        except:
            pass
        self.configure(xscrollcommand=self._autoscroll(hsb))

        self.grid(column=0, row=0, sticky='nsew')
        try:
            vsb.grid(column=1, row=0, sticky='ns')
        except:
            pass
        hsb.grid(column=0, row=1, sticky='ew')

        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(0, weight=1)

        methods = tk.Pack.__dict__.keys() | tk.Grid.__dict__.keys() \
                  | tk.Place.__dict__.keys()

        for m in methods:
            if m[0] != '_' and m not in ('config', 'configure'):
                setattr(self, m, getattr(master, m))

    @staticmethod
    def _autoscroll(sbar):
        '''Hide and show scrollbar as needed.'''

        def wrapped(first, last):
            first, last = float(first), float(last)
            if first <= 0 and last >= 1:
                sbar.grid_remove()
            else:
                sbar.grid()
            sbar.set(first, last)

        return wrapped

    def __str__(self):
        return str(self.master)


def _create_container(func):
    '''Creates a tk Frame with a given master, and use this new frame to
    place the scrollbars and the widget.'''

    def wrapped(cls, master, **kw):
        container = themedFrame(master)
        container.bind('<Enter>', lambda e: _bound_to_mousewheel(e, container))
        container.bind(
            '<Leave>', lambda e: _unbound_to_mousewheel(e, container))
        return func(cls, container, **kw)

    return wrapped


def _bound_to_mousewheel(event, widget):
    child = widget.winfo_children()[0]
    if g_osType == 'Windows' or g_osType == 'Darwin':
        child.bind_all('<MouseWheel>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Shift-MouseWheel>',
                       lambda e: _on_shiftmouse(e, child))
    else:
        child.bind_all('<Button-4>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Button-5>', lambda e: _on_mousewheel(e, child))
        child.bind_all('<Shift-Button-4>', lambda e: _on_shiftmouse(e, child))
        child.bind_all('<Shift-Button-5>', lambda e: _on_shiftmouse(e, child))


def _unbound_to_mousewheel(event, widget):
    if g_osType == 'Windows' or g_osType == 'Darwin':
        widget.unbind_all('<MouseWheel>')
        widget.unbind_all('<Shift-MouseWheel>')
    else:
        widget.unbind_all('<Button-4>')
        widget.unbind_all('<Button-5>')
        widget.unbind_all('<Shift-Button-4>')
        widget.unbind_all('<Shift-Button-5>')


def _on_mousewheel(event, widget):
    if g_osType == 'Windows':
        widget.yview_scroll(-1 * int(event.delta / 120), 'units')
    elif g_osType == 'Darwin':
        widget.yview_scroll(-1 * int(event.delta), 'units')
    else:
        if event.num == 4:
            widget.yview_scroll(-1, 'units')
        elif event.num == 5:
            widget.yview_scroll(1, 'units')


class ScrolledText(AutoScroll, tk.Text):
    @_create_container
    def __init__(self, master, **kw):
        tk.Text.__init__(self, master, **kw)
        AutoScroll.__init__(self, master)


# from https://stackoverflow.com/questions/3221956/how-do-i-display-tooltips-in-tkinter
class CreateToolTip(object):
    '''Creates a tooltip for a passed widget'''
    def __init__(self, widget, text='widget info'):
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.close)

    def enter(self, event=None):
        x = y = 0
        x, y, cx, cy = self.widget.bbox("insert")
        x += self.widget.winfo_rootx()
        y += self.widget.winfo_rooty() + style.scale_measure(20)
        # creates a toplevel window
        self.tw = tk.Toplevel(self.widget)
        # removes the window frame
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tw, text=self.text, justify='left',
                         background='gray', foreground=style.LABEL_COLOR,
                         relief='solid', borderwidth=2,
                         font=style.monospace,
                         wraplength=self.widget.winfo_width())
        label.pack(ipadx=1)

    def close(self, event=None):
        if self.tw: self.tw.destroy()

"""an object to be declared outside of tk root so
    things can be called asyncronously (you cannot start
    a new thread from within a tkinter callback so you
    must call it from an object that exists outside)"""
class threader_object:
    def __init__(self):
        self.threads = []

    def do(self, func, arglist=[]):
        t = threading.Thread(target=func, args=arglist).start()
    
    def do_async(self, func, arglist=[]):
        t = threading.Thread(target=func, args=arglist)
        t.start()
        self.threads.append(t)

    def join(self):
        for t in self.threads:
            t.join()
        self.clear_dead()

    def clear_dead(self):
        self.threads = [t for t in self.threads if t.is_alive()]

class gui(tk.Tk):
    def __init__(self, threader):
        self.threader = threader
        tk.Tk.__init__(self)

        # Set window dimensions.
        window_width_px = style.scale_measure(300)
        window_height_px = style.scale_measure(400)

        pos_hor = int((style.screen_width_px / 2) - (window_width_px / 2))
        pos_ver = int((style.screen_height_px / 2) - (window_height_px / 2))

        self.geometry("{}x{}+{}+{}".format(window_width_px, window_height_px, pos_hor, pos_ver))
        self.title("wad2bin GUI")

        self.f = themedFrame(self)
        self.f.place(relwidth=1, relheight=1)

        outer_frame = themedFrame(self.f)
        outer_frame.place(relwidth=1, relheight=1, x=+ style.STANDARD_OFFSET, width=- 2 * style.STANDARD_OFFSET,
                          y=+ style.STANDARD_OFFSET, height=- 2 * style.STANDARD_OFFSET)

        self.sd_box = LabeledPathEntry(outer_frame, "Path to SD root:", dir=True)
        self.sd_box.place(relwidth=1, height=style.scale_measure(20), x=0)
        CreateToolTip(self.sd_box.xtainer, "Select the root of the SD card you wish to install the WADs to.")

        self.keys_box = LabeledPathEntry(outer_frame, "Path to keys file:", filetypes=[('keys file', '*.txt')])
        self.keys_box.place(relwidth=1, height=style.scale_measure(20), x=0, y=style.scale_measure(30))
        CreateToolTip(self.keys_box.xtainer, "Path to keys file. This can be dumped from a Wii.")

        self.cert_box = LabeledPathEntry(outer_frame, "Path to cert file:", filetypes=[('cert file', '*.cert')])
        self.cert_box.place(relwidth=1, height=style.scale_measure(20), x=0, y=style.scale_measure(60))
        CreateToolTip(self.cert_box.xtainer, "Path to device.cert. This can be dumped from a Wii.")

        self.tid_box = LabeledEntry(outer_frame, "Parent TID (DLC only):")
        self.tid_box.place(relwidth=1, height=style.scale_measure(20), x=0, y=style.scale_measure(90))
        CreateToolTip(self.tid_box.container, """Notes about DLC support:
* Parent title ID is only required if the input WAD is a DLC. A 16 character long hex string is expected.
* If "--nullkey" is set after the parent title ID, a null key will be used to encrypt DLC content data.
  Some older games (like Rock Band 2) depend on this to properly load DLC data when launched via the Disc Channel.""")

        self.use_nullkey = tk.IntVar()
        self.nullkey_checkbutton = tk.Checkbutton(outer_frame, text="Use null key? (DLC only)",
                                                   variable=self.use_nullkey, background=style.BACKGROUND_COLOR,
                                                   foreground=style.LABEL_COLOR, borderwidth=0, highlightthickness=0)
        self.nullkey_checkbutton.place(relwidth=1, y=style.scale_measure(115), height=style.scale_measure(20))
        CreateToolTip(self.nullkey_checkbutton, "Some older games (like Rock Band 2) depend on this to properly load DLC data when launched via the Disc Channel.")

        # -------------------------------------------------
        container = themedFrame(outer_frame, borderwidth=0, highlightthickness=0)
        container.place(y=style.scale_measure(135), relwidth=1, height=style.scale_measure(130))

        path_label = tk.Label(container, text=" - WAD paths - ", foreground=style.LABEL_COLOR,
                             background=style.BACKGROUND_COLOR)
        path_label.place(relwidth=1, height=style.scale_measure(20))
        self.path_box = tk.Listbox(container, highlightthickness=0, bg=style.ENTRY_COLOR,
                                  foreground=style.ENTRY_FOREGROUND)
        self.path_box.place(relwidth=1, height=style.scale_measure(65), y=style.scale_measure(20))
        CreateToolTip(path_label,
                      "Select the WADs you wish to install to the SD card. The `Add folder` button will add all WADs in the selected folder, but will not check subdirs. The `Remove WAD` button will remove the currently selected file from the listbox.")

        button_container = themedFrame(container)
        button_container.place(y = style.scale_measure(90), relwidth = 1, height = style.scale_measure(20))

        self.add_button = Button(button_container, self.add, text="Add WAD", font=style.monospace)
        self.add_button.place(relx=0, relwidth=0.333, height=style.scale_measure(20), width=- style.scale_measure(6))

        self.add_folder_button = Button(button_container, self.add_folder, text="Add folder", font=style.monospace)
        self.add_folder_button.place(relx=0.333, relwidth=0.333, height=style.scale_measure(20), x=+ style.scale_measure(3), width=- style.scale_measure(6))

        self.remove_button = Button(button_container, self.remove, text="Remove WAD", font=style.monospace)
        self.remove_button.place(relx=0.666, relwidth=0.333, height=style.scale_measure(20), x=+ style.scale_measure(6), width=- style.scale_measure(6))

        # -------------------------------------------------

        console_label = tk.Label(outer_frame, text="Console:", background="black", foreground="white",
                                 font=style.boldmonospace, borderwidth=0, highlightthickness=0)
        console_label.place(relwidth=1, height=style.scale_measure(20), y=style.scale_measure(250))
        self.console = ScrolledText(outer_frame, background="black", foreground="white", highlightthickness=0)
        self.console.place(relwidth=1, relheight=1, y=style.scale_measure(270), height= -style.scale_measure(272))
        self.run_button = Button(outer_frame, self.run, text="Run", font=style.boldmonospace)
        self.run_button.place(relwidth=1, rely=1, y=- style.scale_measure(22))

    def run(self):
        self.output_to_console("\n\n-----------------------\nStarting...\n")

        script_name = 'wad2bin'
        if g_osType == 'Windows': script_name += '.exe'

        script = resource_path(script_name)
        if not os.path.exists(script) or os.path.isdir(script):
            self.output_to_console("wad2bin binary can't be found.\nPlease save it to \"%s\".\n" % (script))
            return

        sd = self.sd_box.get().strip()
        if not sd:
            self.output_to_console("Output path (SD card) not selected.\n")
            return
        if len(sd) > 259:
            self.output_to_console("SD card root path too long. Must be less than 259 characters.\n")
            return

        keys = self.keys_box.get().strip()
        if not keys:
            self.output_to_console("No keys.txt provided. This can be dumped from your Wii.\n")
            return
        if len(keys) > 259:
            self.output_to_console("Keys file path too long. Must be less than 259 characters.\n")
            return

        cert = self.cert_box.get().strip()
        if not cert:
            self.output_to_console("No cert provided. This can be dumped from your Wii.\n")
            return
        if len(cert) > 259:
            self.output_to_console("Cert file path too long. Must be less than 259 characters.\n")
            return
    
        tid = self.tid_box.get().strip()

        wads = []
        for i in range(0, self.path_box.size()):
            path = self.path_box.get(i).strip()
            wads.append(path)

        def process_wads(wadlist):
            for wad in wadlist:
                execlist = [script, keys, cert, wad, sd]
                if tid:
                    execlist.append(tid)
                    if self.use_nullkey.get():
                        execlist.append("--nullkey")
                self.threader.do_async(execute_script, [execlist, self.output_to_console])
                self.threader.join() #Wait til complete to start next

        if wads:
            self.disable()
            self.update_idletasks()
            try:
                self.threader.do(process_wads, [wads])
            except Exception as e:
                print(e)
            finally:
                self.enable()
        else:
            self.output_to_console("No WADs selected.\n")

    def output_to_console(self, outstring):
        self.console.insert('end', outstring)
        self.console.see('end')

    def add(self):
        to_add = tkfiledialog.askopenfilename(filetypes=[('WAD file', '*.wad')])
        if to_add:
            self.path_box.insert('end', to_add)

    def add_folder(self):
        dir_to_add = tkfiledialog.askdirectory()
        if dir_to_add:
            to_add = [f for f in os.listdir(dir_to_add) if (os.path.isfile(os.path.join(dir_to_add, f)) and f.endswith(".wad"))]
            if to_add:
                for f in to_add:
                    self.path_box.insert('end', os.path.join(dir_to_add, f))

    def remove(self):
        index = self.path_box.curselection()
        if index:
            self.path_box.delete(index)
            if self.path_box.size():
                self.path_box.select_clear(0, 'end')
                if self.path_box.size() > 1:
                    try:
                        self.path_box.select_set(index)
                    except:
                        pass
                else:
                    self.path_box.select_set(0)

    def disable(self):
        self.path_box.configure(state = "disable")
        self.keys_box.configure(state = "disable")
        self.sd_box.configure(state = "disable")
        self.cert_box.configure(state = "disable")
        self.add_button.configure(state = "disable")
        self.add_folder_button.configure(state = "disable")
        self.remove_button.configure(state = "disable")
        self.run_button.configure(state = "disable")
        self.tid_box.configure(state = "disable")

    def enable(self):
        self.path_box.configure(state = "normal")
        self.keys_box.configure(state = "normal")
        self.sd_box.configure(state = "normal")
        self.cert_box.configure(state = "normal")
        self.add_button.configure(state = "normal")
        self.add_folder_button.configure(state = "normal")
        self.remove_button.configure(state = "normal")
        self.run_button.configure(state = "normal")
        self.tid_box.configure(state = "normal")

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

def execute_script(args, printer):
    p = subprocess.Popen(args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        )

    with p.stdout:
        for line in iter(p.stdout.readline, b''):
            printer(line)
    p.wait()
    # except Exception as e:
    # 	printer(f"Error while executing script with path - {wad_paths} | Exception - {e}\n")

t = threader_object()
window = gui(t)
window.mainloop()
