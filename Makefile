# ===========================================================================
# ██╗ █████╗ ███████╗██╗ ██╗ ███████╗██████╗ █████╗ ███╗   ███╗
# ██║ ██╔══██╗╚══███╔╝╚██╗ ██╔╝ ██╔════╝██╔══██╗██╔══██╗████╗ ████║
# ██║ ███████║  ███╔╝  ╚████╔╝  █████╗  ██████╔╝███████║██╔████╔██║
# ██║ ██╔══██║ ███╔╝   ╚██╔╝   ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║
# ███████╗██║ ███████╗  ██║    ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║
# ╚══════╝╚═╝ ╚══════╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝
#
# P E N T E S T I N G   F R A M E W O R K
# Version: 2.6.0
# ===========================================================================

NAME     := lazyframework
VERSION  := 2.6.0
AUTHOR   := LazyHackers
LICENSE  := GPLv3

# ANSI Color Codes
RESET         := \033[0m
BOLD          := \033[1m
RED           := \033[31m
GREEN         := \033[32m
YELLOW        := \033[33m
BLUE          := \033[34m
MAGENTA       := \033[35m
CYAN          := \033[36m
WHITE         := \033[37m
BRIGHT_RED    := \033[91m
BRIGHT_GREEN  := \033[92m
BRIGHT_YELLOW := \033[93m
BRIGHT_BLUE   := \033[94m
BRIGHT_MAGENTA:= \033[95m
BRIGHT_CYAN   := \033[96m

# Background Colors
BG_RED    := \033[41m
BG_GREEN  := \033[42m
BG_YELLOW := \033[43m
BG_BLUE   := \033[44m
BG_CYAN   := \033[46m

# System Detection
UNAME_S      := $(shell uname -s)
TERMUX_PREFIX:= $(shell echo $$PREFIX 2>/dev/null)

# Default values
IS_TERMUX    := 0
NEED_SUDO    := 0
DISTRO_NAME  := $(UNAME_S)
INSTALL_DIR  := /usr/local/share/$(NAME)
BIN_DIR      := /usr/local/bin
DESKTOP_DIR  := /usr/local/share/applications
ICON_DIR     := /usr/local/share/icons/hicolor/scalable/apps
PIP_CMD      := pip3

# Deteksi Termux
ifeq ($(UNAME_S),Linux)
    ifeq ($(TERMUX_PREFIX),/data/data/com.termux/files/usr)
        IS_TERMUX    := 1
        DISTRO_NAME  := Termux
        INSTALL_DIR  := $(HOME)/$(NAME)
        BIN_DIR      := $(PREFIX)/bin
        DESKTOP_DIR  := $(HOME)/.local/share/applications
        ICON_DIR     := $(HOME)/.local/share/icons/hicolor/scalable/apps
        PIP_CMD      := pip
        NEED_SUDO    := 0
    else
        IS_TERMUX    := 0
        # Deteksi distro modern tanpa lsb_release
        DISTRO_NAME := $(shell \
            if [ -f /etc/os-release ]; then \
                . /etc/os-release && echo "$$NAME" | sed 's/"//g' | awk '{print $$1}'; \
            elif [ -f /etc/debian_version ]; then \
                echo "Debian"; \
            elif [ -f /etc/redhat-release ]; then \
                echo "RedHat"; \
            elif [ -f /etc/arch-release ]; then \
                echo "Arch"; \
            else \
                echo "Linux"; \
            fi \
        )
        INSTALL_DIR  := /usr/share/$(NAME)
        BIN_DIR      := /usr/bin
        DESKTOP_DIR  := /usr/share/applications
        ICON_DIR     := /usr/share/icons/hicolor/scalable/apps
        PIP_CMD      := pip3
        NEED_SUDO    := 1
    endif
endif

.PHONY: all install uninstall clean info help banner check test run-gui install-deps install-binary install-console install-desktop install-icon finish

# ===========================================================================
# DEFAULT TARGET
# ===========================================================================
all: banner header check install
	@echo "All tasks completed."

# ===========================================================================
# BANNER (Metasploit-style)
# ===========================================================================
banner:
	@clear 2>/dev/null || true
	@printf "$(BRIGHT_RED)"
	@echo " ______"
	@echo " .-\"      \"-."
	@echo " /          \\"
	@printf "$(BRIGHT_YELLOW)     $(BRIGHT_RED).$(BRIGHT_YELLOW)           $(BRIGHT_RED)|$(BRIGHT_YELLOW),  $(BRIGHT_RED).$(BRIGHT_YELLOW)-.$(BRIGHT_RED).$(BRIGHT_YELLOW) ,$(BRIGHT_RED)|$(BRIGHT_YELLOW)           $(BRIGHT_RED).$(RESET)\n"
	@printf "$(BRIGHT_YELLOW)     |           |$(BRIGHT_RED)($(BRIGHT_YELLOW) $(BRIGHT_RED).$(BRIGHT_YELLOW)_$(BRIGHT_RED).$(BRIGHT_YELLOW) )$(BRIGHT_RED)|$(BRIGHT_YELLOW)           |$(RESET)\n"
	@printf "$(BRIGHT_YELLOW)  ,  |           |$(BRIGHT_RED)/$(BRIGHT_YELLOW)  $(BRIGHT_RED)|  $(BRIGHT_YELLOW)\\$(BRIGHT_RED)|$(BRIGHT_YELLOW)           |  .$(RESET)\n"
	@printf "$(BRIGHT_YELLOW)  |\\-'           |$(BRIGHT_RED)\`$(BRIGHT_YELLOW)-'$(BRIGHT_RED)|$(BRIGHT_YELLOW)\`$(BRIGHT_RED)|$(BRIGHT_YELLOW)           \`-'|$(RESET)\n"
	@printf "$(BRIGHT_YELLOW)   \\             |$(BRIGHT_RED)'$(BRIGHT_YELLOW)---'$(BRIGHT_RED)'$(BRIGHT_YELLOW)|             /$(RESET)\n"
	@printf "$(BRIGHT_YELLOW)    \\           /'$(BRIGHT_RED).$(BRIGHT_YELLOW)---$(BRIGHT_RED).$(BRIGHT_YELLOW)\`\\           /$(RESET)\n"
	@printf "$(BRIGHT_YELLOW)     \\        /'$(BRIGHT_RED)'$(BRIGHT_YELLOW)---$(BRIGHT_RED)'$(BRIGHT_YELLOW)\`\`\\        /$(RESET)\n"
	@printf "$(BRIGHT_YELLOW)      \`\\    /\`$(BRIGHT_RED)'$(BRIGHT_YELLOW)---$(BRIGHT_RED)'$(BRIGHT_YELLOW)\`\`\`\\    /\`$(RESET)\n"
	@printf "$(BRIGHT_YELLOW)        \`\\/\`$(BRIGHT_RED)'$(BRIGHT_YELLOW)---$(BRIGHT_RED)'$(BRIGHT_YELLOW)\`\`\`\`\\/\`$(RESET)\n"
	@printf "$(BRIGHT_RED)"
	@echo "         =[ $(BRIGHT_YELLOW)lazyframework $(BRIGHT_RED)v$(VERSION) ]="
	@echo ""
	@printf "$(BRIGHT_YELLOW)"
	@echo "    + -- --=[ $(BRIGHT_RED)Pentesting Framework$(BRIGHT_YELLOW) ]"
	@echo "    + -- --=[ $(BRIGHT_RED)Type 'help' for commands$(BRIGHT_YELLOW) ]"
	@echo ""
	@printf "$(RESET)"

# ===========================================================================
# HEADER (SEToolkit-style)
# ===========================================================================
header:
	@printf "$(BRIGHT_CYAN)╔════════════════════════════════════════════════════════════════════════════╗$(RESET)\n"
	@printf "$(BRIGHT_CYAN)║$(RESET)                        $(BRIGHT_RED)LAZYFRAMEWORK v$(VERSION)$(RESET)                         $(BRIGHT_CYAN)║$(RESET)\n"
	@printf "$(BRIGHT_CYAN)╠════════════════════════════════════════════════════════════════════════════╣$(RESET)\n"
	@printf "$(BRIGHT_CYAN)║$(RESET)  $(BRIGHT_WHITE)Platform:$(RESET)  $(BRIGHT_GREEN)$(DISTRO_NAME)$(RESET)                                              $(BRIGHT_CYAN)║$(RESET)\n"
	@printf "$(BRIGHT_CYAN)║$(RESET)  $(BRIGHT_WHITE)Install:$(RESET)  $(BRIGHT_BLUE)$(INSTALL_DIR)$(RESET)                $(BRIGHT_CYAN)║$(RESET)\n"
	@printf "$(BRIGHT_CYAN)╚════════════════════════════════════════════════════════════════════════════╝$(RESET)\n"
	@echo ""

# ===========================================================================
# CHECK SYSTEM
# ===========================================================================
check:
	@printf "$(BRIGHT_YELLOW)[*]$(RESET) Checking system...\n"
	@printf "   Platform    : $(BRIGHT_CYAN)$(DISTRO_NAME)$(RESET)\n"
	@printf "   Install Dir : $(BRIGHT_BLUE)$(INSTALL_DIR)$(RESET)\n"
	@if [ "$(NEED_SUDO)" = "1" ]; then \
		printf "   $(BRIGHT_RED)Root privileges needed$(RESET)\n"; \
	else \
		printf "   $(BRIGHT_GREEN)No sudo required$(RESET)\n"; \
	fi
	@echo ""

# ===========================================================================
# INSTALL DEPENDENCIES
# ===========================================================================
install-deps:
	@printf "$(BRIGHT_YELLOW)[*]$(RESET) Installing dependencies...\n"
	@if [ "$(IS_TERMUX)" = "1" ]; then \
		printf "   Updating pip... "; \
		$(PIP_CMD) install --upgrade pip >/dev/null 2>&1 && printf "$(BRIGHT_GREEN)OK$(RESET)\n" || printf "$(BRIGHT_RED)SKIP$(RESET)\n"; \
		printf "   Installing packages... "; \
		$(PIP_CMD) install rich PyQt6 PyQt6-WebEngine stem requests >/dev/null 2>&1 && printf "$(BRIGHT_GREEN)OK$(RESET)\n" || printf "$(BRIGHT_RED)FAILED$(RESET)\n"; \
	else \
		printf "   Updating pip... "; \
		$(PIP_CMD) install --upgrade pip >/dev/null 2>&1 && printf "$(BRIGHT_GREEN)OK$(RESET)\n" || printf "$(BRIGHT_RED)SKIP$(RESET)\n"; \
		printf "   Installing packages... "; \
		$(PIP_CMD) install rich PyQt6 PyQt6-WebEngine stem requests >/dev/null 2>&1 && printf "$(BRIGHT_GREEN)OK$(RESET)\n" || printf "$(BRIGHT_RED)FAILED$(RESET)\n"; \
	fi
	@echo ""

# ===========================================================================
# INSTALL BINARY FILES
# ===========================================================================
install-binary:
	@printf "$(BRIGHT_YELLOW)[*]$(RESET) Installing framework files...\n"
	@printf "   Creating directory... "
	@if [ "$(NEED_SUDO)" = "1" ]; then \
		sudo mkdir -p "$(INSTALL_DIR)"; \
	else \
		mkdir -p "$(INSTALL_DIR)"; \
	fi
	@printf "$(BRIGHT_GREEN)OK$(RESET)\n"

	@printf "   Copying files... "
	@if [ "$(NEED_SUDO)" = "1" ]; then \
		sudo cp -r *.py bin core modules themes widgets "$(INSTALL_DIR)/" 2>/dev/null || true; \
	else \
		cp -r *.py bin core modules themes widgets "$(INSTALL_DIR)/" 2>/dev/null || true; \
	fi
	@printf "$(BRIGHT_GREEN)OK$(RESET)\n"

	@printf "   Creating launcher... "
	@if [ "$(NEED_SUDO)" = "1" ]; then \
		echo '#!/bin/bash' | sudo tee "$(BIN_DIR)/lazyframework" > /dev/null; \
		echo 'cd "$(INSTALL_DIR)"' | sudo tee -a "$(BIN_DIR)/lazyframework" > /dev/null; \
		echo 'exec python3 gui.py "$$@"' | sudo tee -a "$(BIN_DIR)/lazyframework" > /dev/null; \
		sudo chmod +x "$(BIN_DIR)/lazyframework"; \
	else \
		echo '#!/bin/bash' > "$(BIN_DIR)/lazyframework"; \
		echo 'cd "$(INSTALL_DIR)"' >> "$(BIN_DIR)/lazyframework"; \
		echo 'exec python3 gui.py "$$@"' >> "$(BIN_DIR)/lazyframework"; \
		chmod +x "$(BIN_DIR)/lazyframework"; \
	fi
	@printf "$(BRIGHT_GREEN)OK$(RESET)\n"
	@echo ""

# ===========================================================================
# INSTALL CONSOLE
# ===========================================================================
install-console:
	@printf "$(BRIGHT_YELLOW)[*]$(RESET) Installing console...\n"
	@if [ -f "bin/console.py" ]; then \
		printf "   Creating lzfconsole... "; \
		if [ "$(NEED_SUDO)" = "1" ]; then \
			echo '#!/bin/bash' | sudo tee "$(BIN_DIR)/lzfconsole" > /dev/null; \
			echo 'cd "$(INSTALL_DIR)"' | sudo tee -a "$(BIN_DIR)/lzfconsole" > /dev/null; \
			echo 'exec python3 bin/console.py "$$@"' | sudo tee -a "$(BIN_DIR)/lzfconsole" > /dev/null; \
			sudo chmod +x "$(BIN_DIR)/lzfconsole"; \
		else \
			echo '#!/bin/bash' > "$(BIN_DIR)/lzfconsole"; \
			echo 'cd "$(INSTALL_DIR)"' >> "$(BIN_DIR)/lzfconsole"; \
			echo 'exec python3 bin/console.py "$$@"' >> "$(BIN_DIR)/lzfconsole"; \
			chmod +x "$(BIN_DIR)/lzfconsole"; \
		fi; \
		printf "$(BRIGHT_GREEN)OK$(RESET)\n"; \
	fi
	@echo ""

# ===========================================================================
# INSTALL DESKTOP ENTRY
# ===========================================================================
install-desktop:
	@if [ "$(IS_TERMUX)" = "0" ]; then \
		printf "$(BRIGHT_YELLOW)[*]$(RESET) Installing desktop entry...\n"; \
		printf "   Creating .desktop file... "; \
		if [ "$(NEED_SUDO)" = "1" ]; then \
			sudo mkdir -p "$(DESKTOP_DIR)"; \
			echo '[Desktop Entry]' | sudo tee "$(DESKTOP_DIR)/lazyframework.desktop" > /dev/null; \
			echo 'Version=1.0' | sudo tee -a "$(DESKTOP_DIR)/lazyframework.desktop" > /dev/null; \
			echo 'Type=Application' | sudo tee -a "$(DESKTOP_DIR)/lazyframework.desktop" > /dev/null; \
			echo 'Name=LazyFramework' | sudo tee -a "$(DESKTOP_DIR)/lazyframework.desktop" > /dev/null; \
			echo 'GenericName=Penetration Testing Framework' | sudo tee -a "$(DESKTOP_DIR)/lazyframework.desktop" > /dev/null; \
			echo 'Comment=Professional Security Testing Framework' | sudo tee -a "$(DESKTOP_DIR)/lazyframework.desktop" > /dev/null; \
			echo 'Exec=lazyframework' | sudo tee -a "$(DESKTOP_DIR)/lazyframework.desktop" > /dev/null; \
			echo 'Icon=lazyframework' | sudo tee -a "$(DESKTOP_DIR)/lazyframework.desktop" > /dev/null; \
			echo 'Categories=Utility;Security;Development;' | sudo tee -a "$(DESKTOP_DIR)/lazyframework.desktop" > /dev/null; \
			echo 'Terminal=false' | sudo tee -a "$(DESKTOP_DIR)/lazyframework.desktop" > /dev/null; \
			echo 'StartupNotify=true' | sudo tee -a "$(DESKTOP_DIR)/lazyframework.desktop" > /dev/null; \
			sudo chmod 644 "$(DESKTOP_DIR)/lazyframework.desktop"; \
		else \
			mkdir -p "$(DESKTOP_DIR)"; \
			echo '[Desktop Entry]' > "$(DESKTOP_DIR)/lazyframework.desktop"; \
			echo 'Version=1.0' >> "$(DESKTOP_DIR)/lazyframework.desktop"; \
			echo 'Type=Application' >> "$(DESKTOP_DIR)/lazyframework.desktop"; \
			echo 'Name=LazyFramework' >> "$(DESKTOP_DIR)/lazyframework.desktop"; \
			echo 'GenericName=Penetration Testing Framework' >> "$(DESKTOP_DIR)/lazyframework.desktop"; \
			echo 'Comment=Professional Security Testing Framework' >> "$(DESKTOP_DIR)/lazyframework.desktop"; \
			echo 'Exec=lazyframework' >> "$(DESKTOP_DIR)/lazyframework.desktop"; \
			echo 'Icon=lazyframework' >> "$(DESKTOP_DIR)/lazyframework.desktop"; \
			echo 'Categories=Utility;Security;Development;' >> "$(DESKTOP_DIR)/lazyframework.desktop"; \
			echo 'Terminal=false' >> "$(DESKTOP_DIR)/lazyframework.desktop"; \
			echo 'StartupNotify=true' >> "$(DESKTOP_DIR)/lazyframework.desktop"; \
			chmod 644 "$(DESKTOP_DIR)/lazyframework.desktop"; \
		fi; \
		printf "$(BRIGHT_GREEN)OK$(RESET)\n"; \
		echo ""; \
	fi

# ===========================================================================
# INSTALL ICON
# ===========================================================================
install-icon:
	@if [ "$(IS_TERMUX)" = "0" ]; then \
		printf "$(BRIGHT_YELLOW)[*]$(RESET) Installing icon...\n"; \
		printf "   Creating SVG icon... "; \
		if [ "$(NEED_SUDO)" = "1" ]; then \
			sudo mkdir -p "$(ICON_DIR)"; \
			echo '<?xml version="1.0" encoding="UTF-8"?>' | sudo tee "$(ICON_DIR)/lazyframework.svg" > /dev/null; \
			echo '<svg width="256" height="256" viewBox="0 0 256 256" xmlns="http://www.w3.org/2000/svg">' | sudo tee -a "$(ICON_DIR)/lazyframework.svg" > /dev/null; \
			echo '<rect width="256" height="256" fill="#0d1117" rx="30"/>' | sudo tee -a "$(ICON_DIR)/lazyframework.svg" > /dev/null; \
			echo '<rect x="28" y="28" width="200" height="200" fill="#161b22" rx="15"/>' | sudo tee -a "$(ICON_DIR)/lazyframework.svg" > /dev/null; \
			echo '<text x="128" y="105" text-anchor="middle" font-family="Arial, sans-serif" font-size="36" font-weight="bold" fill="#50fa7b">LF</text>' | sudo tee -a "$(ICON_DIR)/lazyframework.svg" > /dev/null; \
			echo '<text x="128" y="145" text-anchor="middle" font-family="Arial, sans-serif" font-size="18" fill="#8be9fd">Framework</text>' | sudo tee -a "$(ICON_DIR)/lazyframework.svg" > /dev/null; \
			echo '<path d="M60 170 H196 M60 185 H180 M60 200 H160" stroke="#6272a4" stroke-width="4" stroke-linecap="round"/>' | sudo tee -a "$(ICON_DIR)/lazyframework.svg" > /dev/null; \
			echo '</svg>' | sudo tee -a "$(ICON_DIR)/lazyframework.svg" > /dev/null; \
		else \
			mkdir -p "$(ICON_DIR)"; \
			echo '<?xml version="1.0" encoding="UTF-8"?>' > "$(ICON_DIR)/lazyframework.svg"; \
			echo '<svg width="256" height="256" viewBox="0 0 256 256" xmlns="http://www.w3.org/2000/svg">' >> "$(ICON_DIR)/lazyframework.svg"; \
			echo '<rect width="256" height="256" fill="#0d1117" rx="30"/>' >> "$(ICON_DIR)/lazyframework.svg"; \
			echo '<rect x="28" y="28" width="200" height="200" fill="#161b22" rx="15"/>' >> "$(ICON_DIR)/lazyframework.svg"; \
			echo '<text x="128" y="105" text-anchor="middle" font-family="Arial, sans-serif" font-size="36" font-weight="bold" fill="#50fa7b">LF</text>' >> "$(ICON_DIR)/lazyframework.svg"; \
			echo '<text x="128" y="145" text-anchor="middle" font-family="Arial, sans-serif" font-size="18" fill="#8be9fd">Framework</text>' >> "$(ICON_DIR)/lazyframework.svg"; \
			echo '<path d="M60 170 H196 M60 185 H180 M60 200 H160" stroke="#6272a4" stroke-width="4" stroke-linecap="round"/>' >> "$(ICON_DIR)/lazyframework.svg"; \
			echo '</svg>' >> "$(ICON_DIR)/lazyframework.svg"; \
		fi; \
		printf "$(BRIGHT_GREEN)OK$(RESET)\n"; \
		echo ""; \
	fi

# ===========================================================================
# FINISH
# ===========================================================================
finish:
	@printf "$(BRIGHT_GREEN)"
	@echo "   ▄████████    ▄████████    ▄████████    ▄████████ "
	@echo "  ███    ███   ███    ███   ███    ███   ███    ███ "
	@echo "  ███    ███   ███    ███   ███    █▀    ███    █▀  "
	@echo "  ███    ███  ▄███▄▄▄▄██▀  ▄███▄▄▄       ███        "
	@echo "▀███████████ ▀▀███▀▀▀▀▀   ▀▀███▀▀▀     ▀███████████ "
	@echo "  ███    ███ ▀███████████   ███    █▄           ███ "
	@echo "  ███    ███   ███    ███   ███    ███    ▄█    ███ "
	@echo "  ███    █▀    ███    ███   ██████████  ▄████████▀  "
	@echo "               ███    ███                           "
	@printf "$(RESET)"
	@echo ""
	@printf "$(BRIGHT_GREEN)[+]$(RESET) $(BRIGHT_CYAN)LazyFramework v$(VERSION) installed!$(RESET)\n"
	@echo ""
	@printf "   Run: $(BRIGHT_GREEN)lazyframework$(RESET) (GUI) or $(BRIGHT_GREEN)lzfconsole$(RESET) (CLI)\n"
	@echo ""

# ===========================================================================
# INSTALL (Main target)
# ===========================================================================
install: install-deps install-binary install-console install-desktop install-icon finish
	@echo "Installation completed."

# ===========================================================================
# UNINSTALL
# ===========================================================================
uninstall:
	@printf "$(BRIGHT_RED)[!]$(RESET) This will remove LazyFramework!\n"
	@printf "Continue? [y/N] "
	@read answer; \
	if [ "$$answer" = "y" ] || [ "$$answer" = "Y" ]; then \
		printf "   Removing files... "; \
		if [ "$(NEED_SUDO)" = "1" ]; then \
			sudo rm -rf "$(INSTALL_DIR)" 2>/dev/null || true; \
			sudo rm -f "$(BIN_DIR)/lazyframework" "$(BIN_DIR)/lzfconsole" 2>/dev/null || true; \
			if [ "$(IS_TERMUX)" = "0" ]; then \
				sudo rm -f "$(DESKTOP_DIR)/lazyframework.desktop" 2>/dev/null || true; \
				sudo rm -f "$(ICON_DIR)/lazyframework.svg" 2>/dev/null || true; \
			fi; \
		else \
			rm -rf "$(INSTALL_DIR)" 2>/dev/null || true; \
			rm -f "$(BIN_DIR)/lazyframework" "$(BIN_DIR)/lzfconsole" 2>/dev/null || true; \
			if [ "$(IS_TERMUX)" = "0" ]; then \
				rm -f "$(DESKTOP_DIR)/lazyframework.desktop" 2>/dev/null || true; \
				rm -f "$(ICON_DIR)/lazyframework.svg" 2>/dev/null || true; \
			fi; \
		fi; \
		printf "$(BRIGHT_GREEN)OK$(RESET)\n"; \
		printf "$(BRIGHT_GREEN)[✓]$(RESET) LazyFramework uninstalled\n"; \
	else \
		printf "$(BRIGHT_YELLOW)Uninstall cancelled$(RESET)\n"; \
	fi

# ===========================================================================
# DEVELOPMENT SHORTCUTS
# ===========================================================================
run-gui:
	@printf "$(BRIGHT_GREEN)→ Running GUI...$(RESET)\n"
	@python3 gui.py

test:
	@printf "$(BRIGHT_YELLOW)→ Running basic checks...$(RESET)\n"
	@python3 -m py_compile gui.py
	@python3 -m py_compile bin/console.py
	@echo "$(BRIGHT_GREEN)Syntax OK$(RESET)"

clean:
	@find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@printf "$(BRIGHT_GREEN)Cleaned$(RESET)\n"

info:
	@make header

help:
	@echo "Available targets:"
	@echo "  make all          → Show banner + header + check + install"
	@echo "  make install      → Install framework"
	@echo "  make uninstall    → Remove framework"
	@echo "  make clean        → Remove pyc files"
	@echo "  make run-gui      → Run GUI directly"
	@echo "  make test         → Check syntax"
	@echo "  make info         → Show system info"
	@echo "  make help         → This help"

# ===========================================================================
# DEFAULT TARGET
# ===========================================================================
.DEFAULT_GOAL := help