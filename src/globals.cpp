#include "../include/dark_nexus.hpp"

std::mutex  g_print_mtx;
std::mutex  g_result_mtx;
ScanResult  g_result;
CancellationToken g_cancel_token;
