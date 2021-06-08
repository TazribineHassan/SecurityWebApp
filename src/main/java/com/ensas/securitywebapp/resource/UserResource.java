package com.ensas.securitywebapp.resource;

import com.ensas.securitywebapp.Services.UserService;
import com.ensas.securitywebapp.domain.HttpResponse;
import com.ensas.securitywebapp.domain.User;
import com.ensas.securitywebapp.domain.UserPrincipal;
import com.ensas.securitywebapp.exceptions.domain.*;
import com.ensas.securitywebapp.utility.JWTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static com.ensas.securitywebapp.constant.FileConstant.*;
import static com.ensas.securitywebapp.constant.SecurityConstant.JWT_TOKEN_HEADER;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.IMAGE_JPEG_VALUE;

@RestController
@RequestMapping(path= {"/","/user"})
public class UserResource extends ExceptionHandling {

    public static final String USER_DELETED_SUCCESSFULLY = "User deleted successfully";
    public static final String SENT_TO = "An email with new password sent to: ";

    private UserService userService;
    private AuthenticationManager authenticationManager;
    private JWTokenProvider jwTokenProvider;

    @Autowired
    public UserResource(UserService userService, AuthenticationManager authenticationManager, JWTokenProvider jwTokenProvider) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwTokenProvider = jwTokenProvider;
    }

    @PostMapping("/register")
    public ResponseEntity<User>  register(@RequestBody User user) throws UserNotFoundException, UserExistExistException, EmailExistException, MessagingException {
        User newUser = userService.register(user.getFirstName(), user.getLastName(), user.getUsername(), user.getEmail());
        return new ResponseEntity<>(newUser, OK);
    }

    @PostMapping("/login")
    public ResponseEntity<User>  login(@RequestBody User user)  {
        System.out.println("1");
        authentication(user.getUsername(), user.getPassword());
        System.out.println("2");
        User loginUser = userService.findUserByUsername(user.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(loginUser);
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
        return new ResponseEntity<>(loginUser, jwtHeader, OK);
    }

    @PostMapping("/add" )
    public ResponseEntity<User> addUser(@RequestParam("firstName") String firstName,
                                        @RequestParam("lastName") String lastName,
                                        @RequestParam("username") String username,
                                        @RequestParam("email") String email,
                                        @RequestParam("role") String role,
                                        @RequestParam("isActive") String isActive,
                                        @RequestParam("isNonLocked") String isNonLocked,
                                        @RequestParam(value = "profileImage", required = false) MultipartFile profileImage) throws UserNotFoundException, UserExistExistException, EmailExistException, IOException {
        User newUser = userService.addNewUser(firstName, lastName, username, email, role, Boolean.parseBoolean(isNonLocked), Boolean.parseBoolean(isActive), profileImage);
        return  new ResponseEntity<>(newUser, OK);
    }

    @PostMapping("/update" )
    public ResponseEntity<User> apdateUser(@RequestParam("currentUsername") String currentUsername,
                                           @RequestParam("firstName") String firstName,
                                            @RequestParam("lastName") String lastName,
                                            @RequestParam("username") String username,
                                            @RequestParam("email") String email,
                                            @RequestParam("role") String role,
                                            @RequestParam("isActive") String isActive,
                                            @RequestParam("isNonLocked") String isNonLocked,
                                            @RequestParam(value = "profileImage", required = false) MultipartFile profileImage) throws UserNotFoundException, UserExistExistException, EmailExistException, IOException {
        User updateUser = userService.updateUser(currentUsername, firstName, lastName, username, email, role, Boolean.parseBoolean(isNonLocked), Boolean.parseBoolean(isActive), profileImage);
        return  new ResponseEntity<>(updateUser , OK);
    }

    @GetMapping("/find/{username}")
    public ResponseEntity<User> getUser(@PathVariable("username") String username){
        User user = userService.findUserByUsername(username);
        return new ResponseEntity<>(user, OK);
    }

    @GetMapping("/list")
    public ResponseEntity<List<User>> getAllUser(){
        List<User> users = userService.getUsers();
        return new ResponseEntity<>(users, OK);
    }

    @GetMapping("/resetPassword/{email}")
    public ResponseEntity<HttpResponse> resetPassword(@PathVariable("email") String email) throws EmailNotFoundException, MessagingException {
        userService.resetPassword(email);
        return response(OK, SENT_TO + email);
    }

    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasAnyAuthority('user:delete')")
    public ResponseEntity<HttpResponse> deleteUser(@PathVariable("id") int id){
        userService.deleteUser(id);
        return response(NO_CONTENT, USER_DELETED_SUCCESSFULLY);
    }

    @PostMapping("/updateProfileImage" )
    public ResponseEntity<User> updateProfileImage(@RequestParam("username") String username,
                                        @RequestParam(value = "profileImage") MultipartFile profileImage) throws UserNotFoundException, UserExistExistException, EmailExistException, IOException {
        User newUser = userService.updateProfileImage(username,profileImage);
        return  new ResponseEntity<>(newUser, OK);
    }

    @GetMapping(path = "/image/{username}/{fileName}", produces = IMAGE_JPEG_VALUE)
    public byte[] getProfileImage(@PathVariable("username") String username, @PathVariable("fileName") String fileName) throws IOException {
        return Files.readAllBytes(Paths.get(USER_FOLDER + username + FORWARD_SLASH + fileName));
    }

    @GetMapping(path = "/image/{profile}/{username}", produces = IMAGE_JPEG_VALUE)
    public byte[] getTempProfileImage(@PathVariable("username") String username, @PathVariable("fileName") String fileName) throws IOException {
        URL url = new URL(TEMP_PROFILE_IMAGE_BASE_URL+username);
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try(InputStream inputStream = url.openStream()){
            int bytesRead;
            byte[] chunk = new byte[1024];
            while ((bytesRead = inputStream.read(chunk)) > 0){
                stream.write(chunk, 0, bytesRead);
            }
        }
        return stream.toByteArray();
    }

    private ResponseEntity<HttpResponse> response(HttpStatus status, String msg) {
        return new ResponseEntity<>(new HttpResponse(status.value(), status, status.getReasonPhrase(), msg), status);
    }

    private HttpHeaders getJwtHeader(UserPrincipal userPrincipal) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwTokenProvider.generateJwtToken(userPrincipal));
        return headers;
    }

    private void authentication(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }

}
