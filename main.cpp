#include "aes/aes.hpp"
#include <cstring>
#include <cstdio>
#include <iostream>

int main() {
    try {
        std::cout << "=== AES-256-CTR Test Harness ===\n\n";
        std::cout << "Detected: " << aes::aes_path_name(aes::detect_aes_path()) << "\n";
        std::cout << "Active:   " << aes::aes_path_name(aes::active_aes_path()) << "\n\n";

        const std::string msg =
            "The quick brown fox jumps over the lazy dog.\n"
            "AES-256-CTR round-trip test.\n";
        std::vector<std::byte> pt(msg.size());
        std::memcpy(pt.data(), msg.data(), msg.size());

        const std::string pf = "test_pt.bin";
        const std::string ef = "test_enc.aes";
        const std::string kf = "test_key.bin";

        aes::save_file(pt, pf);
        std::cout << "[1] Wrote plaintext -> " << pf << "\n";

        auto key = aes::Key::generate();
        std::cout << "[2] Generated key\n";

        auto loaded = aes::load_file(pf);
        aes::encrypt_to_file(key, loaded, ef);
        std::cout << "[3] Encrypted -> " << ef << "\n";

        key.save_to_file(kf);
        std::cout << "[4] Saved key -> " << kf << " (separate from ciphertext)\n";

        auto k2 = aes::Key::load_from_file(kf);
        auto dec = aes::decrypt_from_file(k2, ef);
        std::cout << "[5] Decrypted\n\n";

        bool ok = (dec.size() == pt.size()) &&
                  (std::memcmp(dec.data(), pt.data(), pt.size()) == 0);
        std::cout << "Round-trip: " << (ok ? "SUCCESS" : "FAILURE") << "\n";

        // Template API
        struct S { int a=42; double b=3.14; char c[8]="hello"; };
        auto k3 = aes::Key::generate();
        S orig{};
        auto e = aes::encrypt_value(k3, orig);
        auto d = aes::decrypt_value<S>(k3, e.nonce, e.ciphertext);
        bool sok = d.a==42 && d.b==3.14 && std::strcmp(d.c,"hello")==0;
        std::cout << "Template:   " << (sok ? "SUCCESS" : "FAILURE") << "\n";

        std::remove(pf.c_str());
        std::remove(ef.c_str());
        std::remove(kf.c_str());
        return (ok && sok) ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 2;
    }
}