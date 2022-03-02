#!/bin/bash
# finish forensics questions before running this. REMEMBER WHAT HAPPENED IN ROUND 2 of CP XII.

echo "Starting ..."

echo "Updating PostGreSQL..."
sudo apt-get install postgresql

# change the below if different postgre version
echo "Starting latest version of PostGreSQL"
sudo systemctl enable postgresql-13

# SQL Functions to run
# postgresql ssl enabled
# no map users to postgres account

echo "Restarting"
sudo systemctl restart postgresql-13
echo "... script has finished"