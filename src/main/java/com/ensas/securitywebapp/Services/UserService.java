package com.ensas.securitywebapp.Services;

import com.ensas.securitywebapp.domain.User;
import com.ensas.securitywebapp.exceptions.domain.EmailExistException;
import com.ensas.securitywebapp.exceptions.domain.EmailNotFoundException;
import com.ensas.securitywebapp.exceptions.domain.UserExistExistException;
import com.ensas.securitywebapp.exceptions.domain.UserNotFoundException;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

public interface UserService {
    User register(String firstName, String lastName, String username, String email) throws UserNotFoundException, UserExistExistException, EmailExistException, MessagingException;
    List<User> getUsers();
    User findUserByUsername(String username);
    User findUserByEmail(String email);
    User addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNonLocked, boolean isActive, MultipartFile file) throws UserNotFoundException, UserExistExistException, EmailExistException, IOException;
    User updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail, String role, boolean isNonLocked, boolean isActive, MultipartFile file) throws UserNotFoundException, UserExistExistException, EmailExistException, IOException;
    void deleteUser(int id);
    void resetPassword(String email) throws EmailNotFoundException, MessagingException;
    User updateProfileImage(String username, MultipartFile file) throws UserNotFoundException, UserExistExistException, EmailExistException, IOException;
}
