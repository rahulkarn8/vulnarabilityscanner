/*
 * Test file with various security vulnerabilities for C++ scanning
 */

#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <new>

// VULNERABILITY: Buffer Overflow - strcpy
void unsafe_copy(char* dest, const char* src) {
    // No bounds checking - buffer overflow risk
    strcpy(dest, src);
}

// VULNERABILITY: Buffer Overflow - strcat
void unsafe_concatenate(char* dest, const char* src) {
    // Unsafe string concatenation
    strcat(dest, src);
}

// VULNERABILITY: Buffer Overflow - sprintf
void unsafe_format(char* buffer, const char* format, const char* value) {
    // No bounds checking in sprintf
    sprintf(buffer, format, value);
}

// VULNERABILITY: Use After Free
void use_after_free_example() {
    int* ptr = new int(42);
    delete ptr;
    // VULNERABILITY: Using pointer after deletion
    *ptr = 100;  // Undefined behavior
    std::cout << *ptr << std::endl;
}

// VULNERABILITY: Memory Leak
void memory_leak_example() {
    int* arr = new int[1000];
    // Memory allocated but never deleted
    // Missing: delete[] arr;
}

// VULNERABILITY: Format String Vulnerability
void format_string_vuln(const char* user_input) {
    // Dangerous - user input as format string
    printf(user_input);
    // Also dangerous
    fprintf(stdout, user_input);
}

// VULNERABILITY: Integer Overflow
void integer_overflow_example() {
    int a = 2147483647;  // Max int value
    int b = a * 2;  // Potential integer overflow
    std::cout << b << std::endl;
}

// VULNERABILITY: Uninitialized Variable
void uninitialized_variable() {
    int x;  // Uninitialized
    int y;  // Uninitialized
    int result = x + y;  // Undefined behavior
    std::cout << result << std::endl;
}

// VULNERABILITY: Null Pointer Dereference (potential)
void null_pointer_deref(int* ptr) {
    if (ptr != nullptr) {
        // This check might not be enough if ptr becomes null later
        *ptr = 42;
    }
    // Missing check before second use
    std::cout << *ptr << std::endl;
}

// VULNERABILITY: Double Free
void double_free_example() {
    int* ptr = new int(42);
    delete ptr;
    delete ptr;  // Double free - undefined behavior
}

// VULNERABILITY: Array Index Out of Bounds (potential)
void array_bounds_vuln(int index) {
    int arr[10];
    // No bounds checking
    arr[index] = 100;  // Potential out of bounds access
    std::cout << arr[index] << std::endl;
}

// VULNERABILITY: Race Condition (potential)
int shared_counter = 0;

void increment_unsafe() {
    // Not thread-safe - potential race condition
    shared_counter++;
}

// VULNERABILITY: Malloc/Free mismatch
void malloc_free_mismatch() {
    int* ptr = (int*)malloc(sizeof(int) * 10);
    // Wrong - should use free, not delete
    delete ptr;  // Should be: free(ptr);
}

// VULNERABILITY: Dangerous function - gets()
void gets_example() {
    char buffer[100];
    // gets() is extremely dangerous - always causes buffer overflow
    // gets(buffer);  // This would cause overflow, commented for safety
}

int main() {
    char dest[10];
    const char* src = "This is a very long string that will overflow";
    
    // Test buffer overflow
    unsafe_copy(dest, src);
    
    // Test format string
    format_string_vuln("%x%x%x%x");
    
    // Test memory issues
    use_after_free_example();
    memory_leak_example();
    
    return 0;
}

