/** */
package com.johnsonautoparts.servlet;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.johnsonautoparts.logger.AppLogger;

/** */
public class SecurityFilter implements Filter {
  /**
   * Called by the web container to indicate to a filter that it is being placed into service. The
   * servlet container calls the init method exactly once after instantiating the filter. The init
   * method must complete successfully before the filter is asked to do any filtering work.
   *
   * @param filterConfig configuration object
   */
  public void init(FilterConfig filterConfig) {
    // initializing steps
  }

  /**
   * The doFilter method of the Filter is called by the container each time a request/response pair
   * is passed through the chain due to a client request for a resource at the end of the chain. The
   * FilterChain passed in to this method allows the Filter to pass on the request and response to
   * the next entity in the chain.
   *
   * @param req Request object to be processed
   * @param resp Response object
   * @param chain current FilterChain
   * @exception IOException if any occurs
   */
  public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
      throws IOException {
    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) resp;
    final String SERVER_HOSTNAME = "localhost";

    try {
      /**
       * Project 4, Milestone 2, Task 6
       *
       * <p>TITLE: Protect the webapp with security headers
       *
       * <p>RISK: Certain headers can help the browser protect the user from attacks: - Limiting the
       * ability to embed the site into a hidden frame (click-jacking) - Change the content-type
       * (MIME Type sniffing) - XSS and data injection attacks
       *
       * <p>REF: SonarSource RSPEC-5122
       *
       * <p>IMPORTANT: Security headers can be injected anywhere the response is available, but care
       * must be taken to account for every flow of the application. Therefore, a class which is
       * always executed, such as a SecurityFilter, is a good option since it is processed before
       * the ServletHandler is executed.
       *
       * <p>Also, there is a note from the developer that Cross Origin headers have been relaxed,
       * this error needs to be fixed as well.
       */
      // AJAX problems so add headers to relax Cross Origin issues
      // TODO: resolve on the GUI to remove this
      /**
       * SOLUTION: The comment from the developer was a hint that headers were relaxed here because
       * of a browser issue. That issue should be resolved.
       *
       * <p>The first line is commented out and changed to the orgin of the real server address:
       *
       * <p>response.setHeader("Access-Control-Allow-Origin", "*");
       */
      response.setHeader("Access-Control-Allow-Origin", "http://localhost:8080/SecureCoding");
      // SOLUTION END

      response.setHeader("Access-Control-Allow-Credentials", "true");
      response.setHeader("Access-Control-Allow-Methods", "GET");

      /**
       * SOLUTION: The following 4 headers are added to the response below. A comment is add for
       * each header to explain the protection. Each application is different and the headers may be
       * too strict if apps are framed in other content or different domains share resources, so you
       * will need to understand what each header does before implementing.
       */
      // click-jacking defense so content cannot be framed from a different website
      response.addHeader("X-Frame-Options", "SAMEORIGIN");

      // forces client to only use content-type sent from server and not try to
      // determine the content type by magic sniffing
      response.addHeader("X-Content-Type-Options", "nosniff");

      // stop caching - this could have a negative performance effect on your website
      // since all content will expire
      response.addHeader("Cache-Control", "no-store");

      // Content-Security-Policy
      // X-Frame-Options is ignored if CSF defined but some browsers ignore so just set this
      response.addHeader("Content-Security-Policy", "frame-ancestors 'none'");
      // SOLUTION END

      // throw an exception if a method other than GET or POST is sent
      if (request.getMethod().equalsIgnoreCase("GET")) {
        // do something with valid GET request
      } else if (request.getMethod().equalsIgnoreCase("POST")) {
        // do something with valid POST request
      }

      /** unknown method Send request to /accessdenied.jsp */
      else {
        sendSecurityError(request, response, "Unknown request verb used: " + request.getMethod());

        return;
      }

      // no errors detected so forward to the next filter
      chain.doFilter(request, response);
    } catch (ServletException se) {
      sendSecurityError(request, response, se.getMessage());
    }
  }

  /**
   * Called by the web container to indicate to a filter that it is being taken out of service. This
   * method is only called once all threads within the filter's doFilter method have exited or after
   * a timeout period has passed. After the web container calls this method, it will not call the
   * doFilter method again on this instance of the filter.
   */
  public void destroy() {
    // finalize
  }

  /**
   * Standardize error sent to user
   *
   * @param request
   */
  // private void sendSecurityError(HttpServletResponse response, String err) {
  private void sendSecurityError(
      HttpServletRequest request, HttpServletResponse response, String err) {
    AppLogger.log("Exception in security filter: " + err);
    // response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR );
    // ServletUtilities.sendError(response, "application error");
    RequestDispatcher dispatcher = request.getRequestDispatcher("/jsp/accessdenied.jsp");

    try {
      dispatcher.forward(request, response);
    } catch (IOException | ServletException e) {
      AppLogger.log("SecurityFilter failed to forward to accessdenied.jsp: " + e.getMessage());
    }
  }
}
