class LogColors:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    ORANGE = "\033[38;5;208m"
    PINK = "\033[38;5;213m"
    LIGHT_GREEN = "\033[38;5;120m"
    LIGHT_BLUE = "\033[38;5;117m"
    VIOLET = "\033[38;5;135m"
    TURQUOISE = "\033[38;5;45m"
    GOLD = "\033[38;5;220m"
    SALMON = "\033[38;5;216m"
    TEAL = "\033[38;5;37m"
    LAVENDER = "\033[38;5;183m"

COLOR_LIST = [
    LogColors.BLUE,
    LogColors.GREEN,
    LogColors.YELLOW,
    LogColors.MAGENTA,
    LogColors.RED,
    LogColors.CYAN,
    LogColors.BRIGHT_BLUE,
    LogColors.BRIGHT_GREEN,
    LogColors.BRIGHT_YELLOW,
    LogColors.BRIGHT_MAGENTA,
    LogColors.BRIGHT_RED,
    LogColors.BRIGHT_CYAN,
    LogColors.BRIGHT_WHITE,
    LogColors.ORANGE,
    LogColors.PINK,
    LogColors.LIGHT_GREEN,
    LogColors.LIGHT_BLUE,
    LogColors.VIOLET,
    LogColors.TURQUOISE,
    LogColors.GOLD,
    LogColors.SALMON,
    LogColors.TEAL,
    LogColors.LAVENDER
]

def colored_log(tag: str, message: str, color: str = LogColors.CYAN):
    """Prints a colored log message."""
    print(f"{color}{tag} {message}{LogColors.RESET}")

