#!/bin/bash

# tmux-session-manager.sh
# A simple tmux session manager script

function show_help() {
    echo "Tmux Session Manager"
    echo "Usage:"
    echo "  ./tmux-session-manager.sh [command]"
    echo ""
    echo "Commands:"
    echo "  list                - List all sessions"
    echo "  new [name]          - Create a new session"
    echo "  attach [name]       - Attach to existing session"
    echo "  kill [name]         - Kill specified session"
    echo "  killall            - Kill all sessions"
    echo "  rename [old] [new]  - Rename session"
    echo "  help               - Show this help message"
}

function list_sessions() {
    echo "Current tmux sessions:"
    tmux list-sessions 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "No active sessions"
    fi
}

function new_session() {
    if [ -z "$1" ]; then
        echo "Please provide a session name"
        return 1
    fi
    
    tmux has-session -t "$1" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "Session '$1' already exists"
        return 1
    fi
    
    tmux new-session -d -s "$1"
    echo "Created new session: $1"
    tmux attach-session -t "$1"
}

function attach_session() {
    if [ -z "$1" ]; then
        echo "Please provide a session name"
        return 1
    fi
    
    tmux has-session -t "$1" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Session '$1' does not exist"
        return 1
    fi
    
    tmux attach-session -t "$1"
}

function kill_session() {
    if [ -z "$1" ]; then
        echo "Please provide a session name"
        return 1
    fi
    
    tmux has-session -t "$1" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Session '$1' does not exist"
        return 1
    fi
    
    tmux kill-session -t "$1"
    echo "Killed session: $1"
}

function kill_all_sessions() {
    tmux kill-server
    echo "Killed all tmux sessions"
}

function rename_session() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "Please provide old and new session names"
        return 1
    fi
    
    tmux has-session -t "$1" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Session '$1' does not exist"
        return 1
    fi
    
    tmux rename-session -t "$1" "$2"
    echo "Renamed session '$1' to '$2'"
}

# Main script logic
case "$1" in
    "list")
        list_sessions
        ;;
    "new")
        new_session "$2"
        ;;
    "attach")
        attach_session "$2"
        ;;
    "kill")
        kill_session "$2"
        ;;
    "killall")
        kill_all_sessions
        ;;
    "rename")
        rename_session "$2" "$3"
        ;;
    "help"|"")
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use 'help' to see available commands"
        exit 1
        ;;
esac
