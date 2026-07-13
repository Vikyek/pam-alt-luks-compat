#!/usr/bin/env python3
import os
import sys
import time
import json
import pwd
import tty
import termios
import subprocess
import re

DEV_PATH = "/dev/sdc1"

THEMES = {
    "caelestia": {
        "name": "Caelestia (Celestial Mauve)",
        "ascii_gradient": ["#c9bfff", "#ffecf3", "#f9b1dc"],
        "border": "#48454f",
        "label": "#e5e1e7",
        "icons": {
            "device": ("💾", "#c8e3ff"),
            "progress": ("📊", "#ceb4eb"),
            "processed": ("📁", "#c9a3fa"),
            "speed": ("⚡", "#c6b6ff"),
            "eta": ("🕒", "#ffecf3"),
            "status": ("🚀", "#f9b1dc")
        },
        "values": {
            "device": "#c9bfff",
            "progress_bar": ["#c6b6ff", "#f9b1dc"],
            "progress_pct": "#f9b1dc",
            "processed": "#e5e1e7",
            "speed": "#c8e3ff",
            "eta": "#ffecf3",
            "status": "#ceb4eb"
        },
        "char_fill": "█",
        "char_empty": "░"
    },
    "cyberpunk": {
        "name": "Midnight Cyber (Neon Cyberpunk)",
        "ascii_gradient": ["#39ff14", "#00ffff", "#ff007f"],
        "border": "#ff007f",
        "label": "#ffffff",
        "icons": {
            "device": ("📟", "#00ffff"),
            "progress": ("💿", "#ff007f"),
            "processed": ("💾", "#39ff14"),
            "speed": ("⚡", "#ffff00"),
            "eta": ("🕒", "#00ffff"),
            "status": ("🛸", "#ff007f")
        },
        "values": {
            "device": "#00ffff",
            "progress_bar": ["#ff007f", "#00ffff"],
            "progress_pct": "#ff007f",
            "processed": "#ffffff",
            "speed": "#39ff14",
            "eta": "#ffff00",
            "status": "#00ffff"
        },
        "char_fill": "━",
        "char_empty": "─"
    },
    "minimalist": {
        "name": "Monochrome Minimal (Clean Slate)",
        "ascii_gradient": ["#ffffff", "#888888", "#ffffff"],
        "border": "#555555",
        "label": "#ffffff",
        "icons": {
            "device": ("", "#ffffff"),
            "progress": ("", "#ffffff"),
            "processed": ("", "#ffffff"),
            "speed": ("", "#ffffff"),
            "eta": ("", "#ffffff"),
            "status": ("", "#ffffff")
        },
        "values": {
            "device": "#aaaaaa",
            "progress_bar": ["#ffffff", "#ffffff"],
            "progress_pct": "#ffffff",
            "processed": "#aaaaaa",
            "speed": "#ffffff",
            "eta": "#aaaaaa",
            "status": "#ffffff"
        },
        "char_fill": "█",
        "char_empty": " "
    },
    "forest": {
        "name": "Forest Moss (Nordic Earthy)",
        "ascii_gradient": ["#8fbcbb", "#a3be8c", "#ebcb8b"],
        "border": "#3b4252",
        "label": "#d8dee9",
        "icons": {
            "device": ("🌲", "#a3be8c"),
            "progress": ("🍂", "#d08770"),
            "processed": ("🪵", "#ebcb8b"),
            "speed": ("⚡", "#bf616a"),
            "eta": ("🕒", "#a3be8c"),
            "status": ("🦌", "#88c0d0")
        },
        "values": {
            "device": "#8fbcbb",
            "progress_bar": ["#a3be8c", "#ebcb8b"],
            "progress_pct": "#ebcb8b",
            "processed": "#d8dee9",
            "speed": "#bf616a",
            "eta": "#a3be8c",
            "status": "#81a1c1"
        },
        "char_fill": "█",
        "char_empty": "▒"
    },
    "oceanic": {
        "name": "Oceanic Drift (Deep Sea)",
        "ascii_gradient": ["#5e81ac", "#81a1c1", "#88c0d0"],
        "border": "#2e3440",
        "label": "#eceff4",
        "icons": {
            "device": ("🐠", "#88c0d0"),
            "progress": ("🌊", "#81a1c1"),
            "processed": ("⚓", "#d8dee9"),
            "speed": ("⚡", "#bf616a"),
            "eta": ("🕒", "#88c0d0"),
            "status": ("🚢", "#b48ead")
        },
        "values": {
            "device": "#88c0d0",
            "progress_bar": ["#81a1c1", "#88c0d0"],
            "progress_pct": "#88c0d0",
            "processed": "#eceff4",
            "speed": "#5e81ac",
            "eta": "#b48ead",
            "status": "#8fbcbb"
        },
        "char_fill": "█",
        "char_empty": "░"
    }
}

ASCII_ART = [
    "   ______           __           __  _     ",
    "  / ____/___ ______/ /__  ______/ /_(_)___ ",
    " / /   / __ `/ ___/ / _ \\/ ___/ __/ / __ \\",
    "/ /___/ /_/ /__  / /  __(__  ) /_/ / /_/ /",
    "\\____/\\__,_/____/_/\\___/____/\\__/_/\\__,_/ "
]

def hex_to_ansi(hex_str, bg=False):
    if not hex_str:
        return ""
    hex_str = hex_str.lstrip('#')
    r, g, b = tuple(int(hex_str[i:i+2], 16) for i in (0, 2, 4))
    code = 48 if bg else 38
    return f"\033[{code};2;{r};{g};{b}m"

def strip_ansi(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def visual_len(text):
    return len(strip_ansi(text))

def get_config_dir():
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return f"/home/{sudo_user}/.config/crypt-progress"
    return os.path.expanduser("~/.config/crypt-progress")

def load_config():
    config_dir = get_config_dir()
    config_file = os.path.join(config_dir, "config.json")
    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                data = json.load(f)
                theme = data.get("theme")
                if theme in THEMES:
                    return theme
        except Exception:
            pass
    return "caelestia"

def save_config(theme_name):
    config_dir = get_config_dir()
    config_file = os.path.join(config_dir, "config.json")
    config_data = {"theme": theme_name}
    
    try:
        os.makedirs(config_dir, exist_ok=True)
        with open(config_file, "w") as f:
            json.dump(config_data, f)
            
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            pw = pwd.getpwnam(sudo_user)
            os.chown(config_dir, pw.pw_uid, pw.pw_gid)
            os.chown(config_file, pw.pw_uid, pw.pw_gid)
    except Exception as e:
        print(f"\033[91mError saving config: {e}\033[0m")

def get_progress():
    try:
        dump = subprocess.check_output(["cryptsetup", "luksDump", DEV_PATH], stderr=subprocess.DEVNULL).decode("utf-8")
        size_bytes = int(subprocess.check_output(["blockdev", "--getsize64", DEV_PATH]).strip())
    except Exception:
        return None, None, False
        
    lines = dump.splitlines()
    crypt_len = 0
    is_reencrypting = False
    
    for line in lines:
        if "reencrypt" in line:
            is_reencrypting = True
            
    for i, line in enumerate(lines):
        if "crypt" in line and "segment" not in line:
            for j in range(i+1, min(i+5, len(lines))):
                if "length:" in lines[j] and "whole device" not in lines[j]:
                    parts = lines[j].split()
                    crypt_len = int(parts[1])
                    break
    
    if not is_reencrypting:
        return size_bytes, size_bytes, True
        
    return crypt_len, size_bytes, False

def format_eta(seconds):
    if seconds < 60:
        return f"{int(seconds)}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{int(minutes)}m {int(seconds % 60)}s"
    hours = minutes / 60
    return f"{int(hours)}h {int(minutes % 60)}m"

def get_key():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
        if ch == '\x1b':
            ch += sys.stdin.read(2)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

def interpolate_color(color_start, color_end, fraction):
    c1 = color_start.lstrip('#')
    c2 = color_end.lstrip('#')
    r1, g1, b1 = int(c1[0:2], 16), int(c1[2:4], 16), int(c1[4:6], 16)
    r2, g2, b2 = int(c2[0:2], 16), int(c2[2:4], 16), int(c2[4:6], 16)
    r = int(r1 + (r2 - r1) * fraction)
    g = int(g1 + (g2 - g1) * fraction)
    b = int(b1 + (b2 - b1) * fraction)
    return f"\033[38;2;{r};{g};{b}m"

def print_ascii_art(theme):
    gradient_colors = theme["ascii_gradient"]
    reset = "\033[0m"
    for line in ASCII_ART:
        line_len = len(line)
        for idx, char in enumerate(line):
            pos = idx / max(1, line_len - 1)
            num_colors = len(gradient_colors)
            color_segment = pos * (num_colors - 1)
            color_idx = int(color_segment)
            fraction = color_segment - color_idx
            
            if color_idx >= num_colors - 1:
                color_idx = num_colors - 2
                fraction = 1.0
                
            color_ansi = interpolate_color(gradient_colors[color_idx], gradient_colors[color_idx + 1], fraction)
            print(color_ansi + char, end="")
        print(reset)

def draw_preview(theme_key, is_selected):
    theme = THEMES[theme_key]
    fill_ansi = hex_to_ansi(theme["values"]["progress_bar"][0])
    empty_ansi = hex_to_ansi(theme["border"])
    reset = "\033[0m"
    
    pct = 50.0
    bar_width = 15
    filled = int(round(bar_width * pct / 100))
    bar = fill_ansi + theme["char_fill"] * filled + empty_ansi + theme["char_empty"] * (bar_width - filled) + reset
    
    selector = "\033[92m➔ \033[0m" if is_selected else "  "
    name_str = f"\033[1m{theme['name']}\033[0m" if is_selected else theme['name']
    
    print(f"{selector}{name_str:<40} {bar} {fill_ansi}{pct:.0f}%{reset}")

def theme_menu():
    current_selection = load_config()
    keys = list(THEMES.keys())
    idx = keys.index(current_selection) if current_selection in keys else 0
    
    print("\033[2J\033[H", end="")
    print("\033[1mSelect a Theme for crypt-progress\033[0m")
    print("Use \033[96mArrow Keys\033[0m (Up/Down) to choose, and press \033[92mEnter\033[0m to select.")
    print("-" * 70)
    print("\n" * len(keys), end="")
    
    try:
        while True:
            print(f"\033[{len(keys)}F", end="")
            for i, key in enumerate(keys):
                draw_preview(key, i == idx)
                
            key = get_key()
            if key == '\x1b[A': # Up
                idx = (idx - 1) % len(keys)
            elif key == '\x1b[B': # Down
                idx = (idx + 1) % len(keys)
            elif key in ('\n', '\r'): # Enter
                selected_theme = keys[idx]
                save_config(selected_theme)
                print(f"\n\033[92mTheme successfully changed to '{THEMES[selected_theme]['name']}'!\033[0m")
                break
            elif key == '\x03': # Ctrl+C
                raise KeyboardInterrupt
    except KeyboardInterrupt:
        print("\nSelection cancelled.")
    sys.exit(0)

def draw_frame_line(theme, icon_data, label, value_str, width=64):
    reset = "\033[0m"
    border_ansi = hex_to_ansi(theme["border"])
    label_ansi = hex_to_ansi(theme["label"])
    
    icon_char, icon_color = icon_data
    icon_ansi = hex_to_ansi(icon_color)
    
    icon_prefix = f"  {icon_ansi}{icon_char}{reset} " if icon_char else "  "
    prefix = f"│{icon_prefix}{label_ansi}{label:<10}{reset}   "
    
    pref_vis_len = visual_len(prefix)
    val_vis_len = visual_len(value_str)
    
    inner_width = width - 2
    padding = inner_width - pref_vis_len - val_vis_len
    if padding < 0:
        padding = 0
        
    line = f"{prefix}{value_str}{' ' * padding}│"
    print(line)

def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("--theme-menu", "-t"):
        theme_menu()
        
    if os.geteuid() != 0:
        print("\033[91mError: This script must be run as root (sudo).\033[0m")
        sys.exit(1)
        
    theme_key = load_config()
    theme = THEMES[theme_key]
    
    border_ansi = hex_to_ansi(theme["border"])
    reset = "\033[0m"
    
    print("\033[2J\033[H", end="") # Clear screen initially
    print_ascii_art(theme)
    print()
    
    print("\n" * 8, end="")
    
    last_len = None
    last_time = None
    speed_history = []
    
    try:
        while True:
            c_len, total, complete = get_progress()
            current_time = time.time()
            
            if c_len is None:
                print("\033[8F", end="")
                print(f"{border_ansi}╭" + "─" * 62 + "╮" + reset)
                print(f"│  \033[91mError: LUKS device {DEV_PATH} not found.\033[0m" + " " * 23 + "│")
                for _ in range(5):
                    print("│" + " " * 62 + "│")
                print(f"{border_ansi}╰" + "─" * 62 + "╯" + reset)
                time.sleep(2)
                continue
                
            pct = (c_len / total) * 100
            
            speed_str = "Calculating..."
            eta_str = "Estimating..."
            
            if last_len is not None and last_time is not None:
                elapsed = current_time - last_time
                if elapsed > 0:
                    bytes_diff = c_len - last_len
                    if bytes_diff > 0:
                        speed = bytes_diff / elapsed
                        speed_history.append(speed)
                        if len(speed_history) > 10:
                            speed_history.pop(0)
                        
                        avg_speed = sum(speed_history) / len(speed_history)
                        speed_str = f"{avg_speed / (1024**2):.2f} MiB/s"
                        
                        remaining_bytes = total - c_len
                        if avg_speed > 0:
                            eta_seconds = remaining_bytes / avg_speed
                            eta_str = format_eta(eta_seconds)
            
            last_len = c_len
            last_time = current_time
            
            v_theme = theme["values"]
            dev_val = f"{hex_to_ansi(v_theme['device'])}{DEV_PATH}{reset}"
            
            bar_width = 20
            filled = int(round(bar_width * pct / 100))
            bar_color_start = v_theme["progress_bar"][0]
            bar_color_end = v_theme["progress_bar"][1]
            
            bar_str = ""
            for idx in range(bar_width):
                if idx < filled:
                    pos = idx / max(1, filled - 1)
                    color = interpolate_color(bar_color_start, bar_color_end, pos)
                    bar_str += color + theme["char_fill"]
                else:
                    bar_str += hex_to_ansi(theme["border"]) + theme["char_empty"]
                    
            prog_val = f"[{bar_str}{reset}] {hex_to_ansi(v_theme['progress_pct'])}\033[1m{pct:.2f}%\033[0m{reset}"
            
            proc_val = f"{hex_to_ansi(v_theme['processed'])}{c_len / (1024**3):.2f} GiB{reset} / {total / (1024**3):.2f} GiB"
            speed_val = f"{hex_to_ansi(v_theme['speed'])}{speed_str}{reset}"
            eta_val = f"{hex_to_ansi(v_theme['eta'])}{eta_str}{reset}"
            status_ansi = hex_to_ansi(v_theme["status"])
            
            # Evaluate status finalization
            if complete:
                is_finalized = os.path.exists("/home/v/encryption_complete.txt")
                if is_finalized or not os.path.exists("/run/luks_keys_to_add.tmp"):
                    status_val = f"{status_ansi}Complete! (Decrypted & Mounted){reset}"
                else:
                    status_val = f"{status_ansi}\033[5mFinalizing (enrolling keys...)\033[0m{reset}"
            else:
                status_val = f"{status_ansi}\033[5mEncrypting...\033[0m{reset}"
            
            print("\033[8F", end="")
            
            print(f"{border_ansi}╭" + "─" * 62 + f"╮{reset}")
            
            draw_frame_line(theme, theme["icons"]["device"], "device", dev_val, 64)
            draw_frame_line(theme, theme["icons"]["progress"], "progress", prog_val, 64)
            draw_frame_line(theme, theme["icons"]["processed"], "processed", proc_val, 64)
            draw_frame_line(theme, theme["icons"]["speed"], "speed", speed_val, 64)
            draw_frame_line(theme, theme["icons"]["eta"], "eta", eta_val, 64)
            draw_frame_line(theme, theme["icons"]["status"], "status", status_val, 64)
            
            print(f"{border_ansi}╰" + "─" * 62 + f"╯{reset}")
            
            if complete and (is_finalized or not os.path.exists("/run/luks_keys_to_add.tmp")):
                break
                
            sys.stdout.flush()
            time.sleep(2)
            
    except KeyboardInterrupt:
        print(f"\n{hex_to_ansi(theme['values']['device'])}Monitor stopped by user.{reset}")

if __name__ == "__main__":
    main()
