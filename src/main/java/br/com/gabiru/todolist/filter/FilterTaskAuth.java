package br.com.gabiru.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.gabiru.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository iUserRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var servletPath = request.getServletPath();
        if(!servletPath.startsWith("/tasks/")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        // pegar a autenticacao (usuario e senha)
        var authorization = request.getHeader("Authorization");
        var authEncoded = authorization.substring("Basic ".length());
        byte[] authDecoded = Base64.getDecoder().decode(authEncoded);
        var authString = new String(authDecoded);
        String[] credentials = authString.split(":");
        String username = credentials[0];
        String password = credentials[1];

        System.out.println(username);
        System.out.println(password);

        // validar usuario
        var user = this.iUserRepository.findByUsername(username);
        if(user == null) {
            response.sendError(401);
        } else {
            // validar a senha
            var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
            if(!passwordVerify.verified) {
                response.sendError(401);
            } else {
                request.setAttribute("idUser", user.getId());
                filterChain.doFilter(request, response);
            }
        }

    }

    
    
}