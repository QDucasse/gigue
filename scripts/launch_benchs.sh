#!/bin/sh
echo "Runnning benchmarks for small methods"
echo " \__  Handling low calls"
python -m benchmarks calls/small_methods_low_calls
echo " \__  Handling med calls"
python -m benchmarks calls/small_methods_med_calls
echo " \__  Handling high calls"
python -m benchmarks calls/small_methods_high_calls

echo "Runnning benchmarks for med methods"
echo " \__  Handling low calls"
python -m benchmarks calls/medium_methods_low_calls
echo " \__  Handling med calls"
python -m benchmarks calls/medium_methods_med_calls
echo " \__  Handling high calls"
python -m benchmarks calls/medium_methods_high_calls

echo "Runnning benchmarks for large methods"
echo " \__  Handling low calls"
python -m benchmarks calls/large_methods_low_calls
echo " \__  Handling med calls"
python -m benchmarks calls/large_methods_med_calls
echo " \__  Handling high calls"
python -m benchmarks calls/large_methods_high_calls




echo "Runnning benchmarks for small methods"
echo " \__  Handling low mem access"
python -m benchmarks memory/small_methods_low_mem
echo " \__  Handling med mem access"
python -m benchmarks memory/small_methods_med_mem
echo " \__  Handling high calls"
python -m benchmarks memory/small_methods_high_mem

echo "Runnning benchmarks for med methods"
echo " \__  Handling low mem access"
python -m benchmarks memory/medium_methods_low_mem
echo " \__  Handling med mem access"
python -m benchmarks memory/medium_methods_med_mem
echo " \__  Handling high mem access"
python -m benchmarks memory/medium_methods_high_mem

echo "Runnning benchmarks for large methods"
echo " \__  Handling low mem access"
python -m benchmarks memory/large_methods_low_mem
echo " \__  Handling med mem access"
python -m benchmarks memory/large_methods_med_mem
echo " \__  Handling high mem access"
python -m benchmarks memory/large_methods_high_mem