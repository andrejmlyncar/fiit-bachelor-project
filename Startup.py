import config
from ConsoleApplication import UiApplication
from GuiApplication import GuiMain


if config.gui_mode:
    app = GuiMain()
    app.main()
else:
    app = UiApplication()
    app.start_ui()
