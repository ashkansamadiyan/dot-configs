#!/bin/bash
# Navigate to your project directory
cd ~/projects/live/next/ || { echo "Directory not found"; exit 1; }

# Create a new tmux session named "next" with the first window also named "next"
tmux new-session -d -s next -n next

# In the first window ("next"): switch to frontend and open nvim
tmux send-keys -t next:next 'cd frontend && nvim .' C-m

# Create a second window named "dj": switch to backend, activate the virtualenv, and open nvim
tmux new-window -t next: -n dj
tmux send-keys -t next:dj 'cd backend && source venv/bin/activate && nvim .' C-m

# Create a third window named "servers"
tmux new-window -t next: -n servers

# In the "servers" window, in the first pane (pane 0):
# Change to frontend and run "bun devt"
tmux send-keys -t next:servers 'cd frontend && bun devt' C-m

# Split the window vertically (side-by-side) and capture the new pane id
right_pane=$(tmux split-window -h -t next:servers -P -F '#{pane_id}')

# In the new pane, change to backend, activate virtualenv, and run the Django server
tmux send-keys -t "$right_pane" 'cd backend && source venv/bin/activate && python manage.py runserver 0.0.0.0:8001' C-m

# Finally, attach to the tmux session
tmux attach -t next

