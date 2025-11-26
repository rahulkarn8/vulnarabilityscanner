/*
 * Safer version showing how to fix C++ vulnerabilities
 * This file should have fewer or no vulnerabilities
 */

#include <iostream>
#include <string>
#include <cstring>
#include <memory>
#include <vector>
#include <limits>

// FIXED: Use std::string instead of C-style strings
void safe_copy(std::string& dest, const std::string& src) {
    // Safe - std::string handles memory automatically
    dest = src;
}

// FIXED: Use strncpy with bounds checking
void safe_copy_cstyle(char* dest, const char* src, size_t dest_size) {
    if (dest_size == 0) return;
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';  // Ensure null termination
}

// FIXED: Use smart pointers instead of raw pointers
void safe_memory_management() {
    // std::unique_ptr automatically deletes when out of scope
    std::unique_ptr<int> ptr = std::make_unique<int>(42);
    // No need to delete - automatically handled
}

// FIXED: Use std::vector instead of new[]
void safe_array() {
    // std::vector handles memory automatically
    std::vector<int> arr(1000);
    // No need to delete - automatically handled
}

// FIXED: Format String - Always use format specifiers
void safe_format(const char* user_input) {
    // Safe - explicit format specifier
    printf("%s", user_input);
    std::cout << user_input << std::endl;  // Even better - use iostreams
}

// FIXED: Integer Overflow - Check bounds
void safe_integer_operation(int a, int b) {
    // Check for overflow before operation
    if (a > 0 && b > std::numeric_limits<int>::max() - a) {
        throw std::overflow_error("Integer overflow");
    }
    int result = a + b;
    std::cout << result << std::endl;
}

// FIXED: Initialize all variables
void safe_variables() {
    int x = 0;  // Initialized
    int y = 0;  // Initialized
    int result = x + y;
    std::cout << result << std::endl;
}

// FIXED: Proper null pointer checking
void safe_pointer_use(int* ptr) {
    if (ptr == nullptr) {
        std::cerr << "Null pointer error" << std::endl;
        return;
    }
    *ptr = 42;
    std::cout << *ptr << std::endl;
}

// FIXED: Use std::shared_ptr for shared ownership
void safe_shared_pointer() {
    std::shared_ptr<int> shared = std::make_shared<int>(42);
    // Safe shared ownership
}

// FIXED: Array bounds checking
void safe_array_access(int index) {
    const int SIZE = 10;
    int arr[SIZE];
    
    // Bounds checking
    if (index < 0 || index >= SIZE) {
        std::cerr << "Index out of bounds" << std::endl;
        return;
    }
    arr[index] = 100;
    std::cout << arr[index] << std::endl;
}

// FIXED: Use std::mutex for thread safety
#include <mutex>
std::mutex counter_mutex;
int shared_counter = 0;

void safe_increment() {
    // Thread-safe increment
    std::lock_guard<std::mutex> lock(counter_mutex);
    shared_counter++;
}

int main() {
    // Safe examples
    std::string dest;
    std::string src = "This is a safe string";
    safe_copy(dest, src);
    
    safe_format("Hello, World!");
    safe_memory_management();
    safe_array();
    
    return 0;
}

