@echo off
cd /d C:\Users\trex2\Potential-Gold\Zero-Day
python -u detection\eval_external_ids2018.py --seeds 0 1 2 3 > experiments\ids2018_multiseed.log 2>&1
python -u detection\eval_external_ctu13.py --seeds 0 1 2 3 > experiments\ctu13_multiseed.log 2>&1
