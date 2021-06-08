package com.ensas.securitywebapp.Services.implementaions;

import com.ensas.securitywebapp.Services.EmailService;
import com.ensas.securitywebapp.Services.LoginAttemptService;
import com.ensas.securitywebapp.Services.UserService;
import com.ensas.securitywebapp.domain.User;
import com.ensas.securitywebapp.domain.UserPrincipal;
import com.ensas.securitywebapp.enumeration.Role;
import com.ensas.securitywebapp.exceptions.domain.EmailExistException;
import com.ensas.securitywebapp.exceptions.domain.EmailNotFoundException;
import com.ensas.securitywebapp.exceptions.domain.UserExistExistException;
import com.ensas.securitywebapp.exceptions.domain.UserNotFoundException;
import com.ensas.securitywebapp.repositories.UserRepository;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.mail.MessagingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import static com.ensas.securitywebapp.constant.FileConstant.*;
import static com.ensas.securitywebapp.constant.UserImplementationConstant.*;
import static com.ensas.securitywebapp.enumeration.Role.ROLE_USER;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

@Service
@Transactional
@Qualifier("UserDetailsService")
public class UserServiceImpl implements UserService, UserDetailsService {

    private Logger logger = LoggerFactory.getLogger(getClass());
    private UserRepository userRepository;
    private BCryptPasswordEncoder passwordEncoder;
    private LoginAttemptService loginAttemptService;
    private EmailService emailService;

    @Autowired
    public UserServiceImpl(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder, LoginAttemptService loginAttemptService, EmailService emailService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder; 
        this.loginAttemptService = loginAttemptService;
        this.emailService = emailService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(username);
        if(user == null){
            logger.error(NO_USER_FOUND_BY_USERNAME + username);
            throw new UsernameNotFoundException(NO_USER_FOUND_BY_USERNAME + username);
        }else {
            validateLoginAttempt(user);
            user.setLastLoginDateDisplay(user.getLastLoginDate());
            user.setLastLoginDate(new Date());
            userRepository.save(user);
            UserPrincipal userPrincipal = new UserPrincipal(user);
            logger.info("Returning found by username :" + username);
            return  userPrincipal;
        }
    }

    private void validateLoginAttempt(User user) {
        if(user.isNotLocked()){
            if(loginAttemptService.hasExceededMaxAttempts(user.getUsername())){
                user.setNotLocked(false);
            }else {
                user.setNotLocked(true);
            }
        }else {
            loginAttemptService.evictUserFromLoginAttemptCache(user.getUsername());
        }
    }

    @Override
    public User register(String firstName, String lastName, String username, String email) throws UserNotFoundException, UserExistExistException, EmailExistException, MessagingException {
        validateNewUsernameAndEmail(StringUtils.EMPTY, username, email);
        User user = new User();
        user.setCode_employee(generateCodeEmployee());
        String password = generatePassword();
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setUsername(username);
        user.setEmail(email);
        user.setJoinDate(new Date());
        user.setPassword(encodePassword(password));
        user.setActive(true);
        user.setNotLocked(true);
        user.setRoles(ROLE_USER.name());
        user.setAuthorities(ROLE_USER.getAuthorities());
        user.setProfileImageUrl(getTemporaryProfileImageUrl(username));
        emailService.sendNewPasswordEmail(firstName, password, email);
        logger.info("New user password: " + password);
        this.userRepository.save(user);
        return user;
    }




    @Override
    public List<User> getUsers() {
        return this.userRepository.findAll();
    }

    @Override
    public User findUserByUsername(String username) {
        return this.userRepository.findUserByUsername(username);
    }

    @Override
    public User findUserByEmail(String email) {
        return this.userRepository.findUserByEmail(email);
    }

    @Override
    public User addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNonLocked, boolean isActive, MultipartFile file) throws UserNotFoundException, UserExistExistException, EmailExistException, IOException {
        validateNewUsernameAndEmail(StringUtils.EMPTY, username, email);
        User user = new User();
        user.setCode_employee(generateCodeEmployee());
        String  password = generatePassword();
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setUsername(username);
        user.setEmail(email);
        user.setJoinDate(new Date());
        user.setPassword(encodePassword(password));
        user.setActive(isActive);
        user.setNotLocked(isNonLocked);
        user.setRoles(getRoleEnumName(role).name());
        user.setAuthorities(getRoleEnumName(role).getAuthorities());
        user.setProfileImageUrl(getTemporaryProfileImageUrl(username));
        //emailService.sendNewPasswordEmail(firstName, password, email);
        logger.info("New user password: " + password);
        saveProfileImage(user, file);
        this.userRepository.save(user);
        return user;
    }

    @Override
    public User updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail, String role, boolean isNonLocked, boolean isActive, MultipartFile file) throws UserNotFoundException, UserExistExistException, EmailExistException, IOException {
        User user = validateNewUsernameAndEmail(currentUsername, newUsername, newEmail);
        user.setFirstName(newFirstName);
        user.setLastName(newLastName);
        user.setUsername(newUsername);
        user.setEmail(newEmail);
        user.setActive(isActive);
        user.setNotLocked(isNonLocked);
        user.setRoles(getRoleEnumName(role).name());
        user.setAuthorities(getRoleEnumName(role).getAuthorities());
        saveProfileImage(user, file);
        this.userRepository.save(user);
        return user;
    }

    @Override
    public void deleteUser(int id) {
    userRepository.deleteById(id);
    }

    @Override
    public void resetPassword(String email) throws EmailNotFoundException, MessagingException {
        User user  = userRepository.findUserByEmail(email);
        if(user == null){
            throw new EmailNotFoundException(NO_USER_FOUND_BY_EMAIL + email);
        }
        String password = generatePassword();
        user.setPassword(encodePassword(password));
        userRepository.save(user);
        emailService.sendNewPasswordEmail(user.getFirstName(), password, email);
    }

    @Override
    public User updateProfileImage(String username, MultipartFile file) throws UserNotFoundException, UserExistExistException, EmailExistException, IOException {
        User user = validateNewUsernameAndEmail(username, null, null);
        saveProfileImage(user, file);
        return user;
    }

    private void saveProfileImage(User user, MultipartFile file) throws IOException {
        if(file != null){
            Path userFolder = Paths.get(USER_FOLDER + user.getUsername()).toAbsolutePath().normalize();
            if(!Files.exists(userFolder)){
                Files.createDirectories(userFolder);
                logger.info(DIRECTORY_CREATED);
            }
            Files.deleteIfExists(Paths.get(userFolder + user.getUsername() + DOT + JPG_EXTENSION));
            Files.copy(file.getInputStream(), userFolder.resolve(user.getUsername() + DOT + JPG_EXTENSION), REPLACE_EXISTING);
            user.setProfileImageUrl(setProfileImageUrl(user.getUsername()));
            userRepository.save(user);
            logger.info(FILE_SAVED_IN_FILE_SYSTEM + file.getOriginalFilename());
        }
    }

    private String setProfileImageUrl(String username) {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path(USER_IMAGE_PATH + username + FORWARD_SLASH + username + DOT + JPG_EXTENSION ).toUriString();
    }

    private Role getRoleEnumName(String role) {
        return Role.valueOf(role.toUpperCase(Locale.ROOT));
    }

    private String getTemporaryProfileImageUrl(String username) {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path(DEFAULT_USER_IMAGE_PATH + username).toUriString();
    }

    private String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }

    private String generatePassword() {
        return RandomStringUtils.randomAlphanumeric(10);
    }

    private String generateCodeEmployee() {
        return RandomStringUtils.randomNumeric(10);
    }


    private User validateNewUsernameAndEmail(String currentUsername, String username, String  email) throws UserNotFoundException, UserExistExistException, EmailExistException {

        User userByUsername = findUserByUsername(username);
        User userByEmail = findUserByEmail(email);

        if(StringUtils.isNotBlank(currentUsername)){
            User currentUser = findUserByUsername(currentUsername);
            if(currentUser == null){
                throw new UserNotFoundException(NO_USER_FOUND_BY_USERNAME +  currentUsername);
            }
            if(userByUsername != null && !(currentUser.getId() + "").equals(userByUsername.getId())){
                throw new UserExistExistException(USERNAME_IS_ALREADY_EXIST);
            }
            if(userByEmail != null && !(currentUser.getId() + "").equals(userByEmail.getId())){
                throw new EmailExistException(EMAIL_IS_ALREADY_EXIST);
            }
            return currentUser;
        }else {
            if(userByUsername != null ){
                throw new UserExistExistException(USERNAME_IS_ALREADY_EXIST);
            }
            if(userByEmail != null){
                throw new EmailExistException(EMAIL_IS_ALREADY_EXIST);
            }

            return null;
        }
    }
}
