package net.khoury.elie.config.web.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.io.DataInputStream;
import java.io.IOException;

/**
 * Created by elie on 06.03.16.
 */
public class PasswordGenerator {

    public static void main(String[] args) throws IOException {
        System.out.print("Enter the text to hash: ");
        DataInputStream inputStream = new DataInputStream(System.in);

        System.out.println("Hashed text: " + new BCryptPasswordEncoder(10).encode(inputStream.readUTF()));
    }
}
