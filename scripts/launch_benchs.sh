#!/bin/sh
echo "Runnning benchmarks for small methods"
echo " \__  Handling low calls"
python -m benchmarks small_methods_low_calls
echo " \__  Handling med calls"
python -m benchmarks small_methods_med_calls
echo " \__  Handling high calls"
python -m benchmarks small_methods_high_calls

echo "Runnning benchmarks for med methods"
echo " \__  Handling low calls"
python -m benchmarks medium_methods_low_calls
echo " \__  Handling med calls"
python -m benchmarks medium_methods_med_calls
echo " \__  Handling high calls"
python -m benchmarks medium_methods_high_calls

echo "Runnning benchmarks for large methods"
echo " \__  Handling low calls"
python -m benchmarks large_methods_low_calls
echo " \__  Handling med calls"
python -m benchmarks large_methods_med_calls
echo " \__  Handling high calls"
python -m benchmarks large_methods_high_calls