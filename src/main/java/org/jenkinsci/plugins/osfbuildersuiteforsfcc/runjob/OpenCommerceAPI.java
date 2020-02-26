package org.jenkinsci.plugins.osfbuildersuiteforsfcc.runjob;

import com.google.gson.*;
import hudson.AbortException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.*;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.GzipDecompressingEntity;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.*;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.HTTPProxyCredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.OpenCommerceAPICredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.runjob.repeatable.JobArgument;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Stream;

class OpenCommerceAPI {
    private String hostname;
    private HTTPProxyCredentials httpProxyCredentials;
    private Boolean disableSSLValidation;
    private OpenCommerceAPICredentials ocCredentials;
    private String ocVersion;
    private String jobName;
    private List<JobArgument> jobArguments;

    private String cacheAuthType;
    private String cacheAuthToken;
    private Long cacheAuthExpire;
    
    OpenCommerceAPI(
            String hostname,
            HTTPProxyCredentials httpProxyCredentials,
            Boolean disableSSLValidation,
            OpenCommerceAPICredentials ocCredentials,
            String ocVersion,
            String jobName,
            List<JobArgument> jobArguments) throws IOException {

        this.hostname = hostname;
        this.httpProxyCredentials = httpProxyCredentials;
        this.disableSSLValidation = disableSSLValidation;
        this.ocCredentials = ocCredentials;
        this.ocVersion = ocVersion;
        this.jobName = jobName;
        this.jobArguments = jobArguments;

        this.cacheAuthType = "";
        this.cacheAuthToken = "";
        this.cacheAuthExpire = 0L;
    }

    private CloseableHttpClient getCloseableHttpClient() throws AbortException {
        HttpClientBuilder httpClientBuilder = HttpClients.custom();
        httpClientBuilder.setUserAgent("Jenkins (OSF Builder Suite For Salesforce Commerce Cloud)");
        httpClientBuilder.setDefaultCookieStore(new BasicCookieStore());

        httpClientBuilder.addInterceptorFirst((HttpRequestInterceptor) (request, context) -> {
            if (!request.containsHeader("Accept-Encoding")) {
                request.addHeader("Accept-Encoding", "gzip");
            }
        });

        httpClientBuilder.addInterceptorFirst((HttpResponseInterceptor) (response, context) -> {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                Header header = entity.getContentEncoding();
                if (header != null) {
                    for (HeaderElement headerElement : header.getElements()) {
                        if (headerElement.getName().equalsIgnoreCase("gzip")) {
                            response.setEntity(new GzipDecompressingEntity(response.getEntity()));
                            return;
                        }
                    }
                }
            }
        });

        httpClientBuilder.setDefaultConnectionConfig(ConnectionConfig.custom()
                .setBufferSize(5242880 /* 5 MegaBytes */)
                .setFragmentSizeHint(5242880 /* 5 MegaBytes */)
                .build()
        );

        httpClientBuilder.setDefaultRequestConfig(RequestConfig.custom()
                .setSocketTimeout(300000 /* 5 minutes */)
                .setConnectTimeout(300000 /* 5 minutes */)
                .setConnectionRequestTimeout(300000 /* 5 minutes */)
                .build()
        );

        // Proxy Auth
        if (httpProxyCredentials != null) {
            String httpProxyHost = httpProxyCredentials.getHost();
            String httpProxyPort = httpProxyCredentials.getPort();
            String httpProxyUsername = httpProxyCredentials.getUsername();
            String httpProxyPassword = httpProxyCredentials.getPassword().getPlainText();

            int httpProxyPortInteger;

            try {
                httpProxyPortInteger = Integer.parseInt(httpProxyPort);
            } catch (NumberFormatException e) {
                throw new AbortException(
                        String.format("Invalid value \"%s\" for HTTP proxy port!", httpProxyPort) + " " +
                                "Please enter a valid port number."
                );
            }

            if (httpProxyPortInteger <= 0 || httpProxyPortInteger > 65535) {
                throw new AbortException(
                        String.format("Invalid value \"%s\" for HTTP proxy port!", httpProxyPort) + " " +
                                "Please enter a valid port number."
                );
            }

            HttpHost httpClientProxy = new HttpHost(httpProxyHost, httpProxyPortInteger);
            httpClientBuilder.setProxy(httpClientProxy);

            CredentialsProvider httpCredentialsProvider = new BasicCredentialsProvider();

            if (StringUtils.isNotEmpty(httpProxyUsername) && StringUtils.isNotEmpty(httpProxyPassword)) {
                if (httpProxyUsername.contains("\\")) {
                    String domain = httpProxyUsername.substring(0, httpProxyUsername.indexOf("\\"));
                    String user = httpProxyUsername.substring(httpProxyUsername.indexOf("\\") + 1);

                    httpCredentialsProvider.setCredentials(
                            new AuthScope(httpProxyHost, httpProxyPortInteger),
                            new NTCredentials(user, httpProxyPassword, "", domain)
                    );
                } else {
                    httpCredentialsProvider.setCredentials(
                            new AuthScope(httpProxyHost, httpProxyPortInteger),
                            new UsernamePasswordCredentials(httpProxyUsername, httpProxyPassword)
                    );
                }
            }

            httpClientBuilder.setDefaultCredentialsProvider(httpCredentialsProvider);
        }

        return httpClientBuilder.build();
    }

    private CloseableHttpClient getCloseableHttpClientWithCustomSSLSettings() throws AbortException {
        HttpClientBuilder httpClientBuilder = HttpClients.custom();
        httpClientBuilder.setUserAgent("Jenkins (OSF Builder Suite For Salesforce Commerce Cloud)");
        httpClientBuilder.setDefaultCookieStore(new BasicCookieStore());

        httpClientBuilder.addInterceptorFirst((HttpRequestInterceptor) (request, context) -> {
            if (!request.containsHeader("Accept-Encoding")) {
                request.addHeader("Accept-Encoding", "gzip");
            }
        });

        httpClientBuilder.addInterceptorFirst((HttpResponseInterceptor) (response, context) -> {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                Header header = entity.getContentEncoding();
                if (header != null) {
                    for (HeaderElement headerElement : header.getElements()) {
                        if (headerElement.getName().equalsIgnoreCase("gzip")) {
                            response.setEntity(new GzipDecompressingEntity(response.getEntity()));
                            return;
                        }
                    }
                }
            }
        });

        httpClientBuilder.setDefaultConnectionConfig(ConnectionConfig.custom()
                .setBufferSize(5242880 /* 5 MegaBytes */)
                .setFragmentSizeHint(5242880 /* 5 MegaBytes */)
                .build()
        );

        httpClientBuilder.setDefaultRequestConfig(RequestConfig.custom()
                .setSocketTimeout(300000 /* 5 minutes */)
                .setConnectTimeout(300000 /* 5 minutes */)
                .setConnectionRequestTimeout(300000 /* 5 minutes */)
                .build()
        );

        // Proxy Auth
        if (httpProxyCredentials != null) {
            String httpProxyHost = httpProxyCredentials.getHost();
            String httpProxyPort = httpProxyCredentials.getPort();
            String httpProxyUsername = httpProxyCredentials.getUsername();
            String httpProxyPassword = httpProxyCredentials.getPassword().getPlainText();

            int httpProxyPortInteger;

            try {
                httpProxyPortInteger = Integer.parseInt(httpProxyPort);
            } catch (NumberFormatException e) {
                throw new AbortException(
                        String.format("Invalid value \"%s\" for HTTP proxy port!", httpProxyPort) + " " +
                                "Please enter a valid port number."
                );
            }

            if (httpProxyPortInteger <= 0 || httpProxyPortInteger > 65535) {
                throw new AbortException(
                        String.format("Invalid value \"%s\" for HTTP proxy port!", httpProxyPort) + " " +
                                "Please enter a valid port number."
                );
            }

            HttpHost httpClientProxy = new HttpHost(httpProxyHost, httpProxyPortInteger);
            httpClientBuilder.setProxy(httpClientProxy);

            CredentialsProvider httpCredentialsProvider = new BasicCredentialsProvider();

            if (StringUtils.isNotEmpty(httpProxyUsername) && StringUtils.isNotEmpty(httpProxyPassword)) {
                if (httpProxyUsername.contains("\\")) {
                    String domain = httpProxyUsername.substring(0, httpProxyUsername.indexOf("\\"));
                    String user = httpProxyUsername.substring(httpProxyUsername.indexOf("\\") + 1);

                    httpCredentialsProvider.setCredentials(
                            new AuthScope(httpProxyHost, httpProxyPortInteger),
                            new NTCredentials(user, httpProxyPassword, "", domain)
                    );
                } else {
                    httpCredentialsProvider.setCredentials(
                            new AuthScope(httpProxyHost, httpProxyPortInteger),
                            new UsernamePasswordCredentials(httpProxyUsername, httpProxyPassword)
                    );
                }
            }

            httpClientBuilder.setDefaultCredentialsProvider(httpCredentialsProvider);
        }

        if (disableSSLValidation != null && disableSSLValidation) {
            SSLContextBuilder sslContextBuilder = SSLContexts.custom();

            try {
                sslContextBuilder.loadTrustMaterial(null, (TrustStrategy) (arg0, arg1) -> true);
            } catch (NoSuchAlgorithmException | KeyStoreException e) {
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while setting up the custom key store!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            SSLContext customSSLContext;

            try {
                customSSLContext = sslContextBuilder.build();
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                AbortException abortException = new AbortException(String.format(
                        "Exception thrown while creating custom SSL context!\n%s",
                        ExceptionUtils.getStackTrace(e)
                ));
                abortException.initCause(e);
                throw abortException;
            }

            httpClientBuilder.setSSLSocketFactory(
                    new SSLConnectionSocketFactory(
                            customSSLContext, NoopHostnameVerifier.INSTANCE
                    )
            );
        }

        return httpClientBuilder.build();
    }

    private AuthResponse auth() throws IOException {
        Long currentTs = new Date().getTime() / 1000L;
        if (cacheAuthExpire > currentTs) {
            return new AuthResponse(cacheAuthToken, cacheAuthType);
        }

        List<NameValuePair> httpPostParams = new ArrayList<>();
        httpPostParams.add(new BasicNameValuePair("grant_type", "client_credentials"));

        RequestBuilder requestBuilder = RequestBuilder.create("POST");
        requestBuilder.setHeader("Authorization", String.format(
                "Basic %s",
                Base64.getEncoder().encodeToString(
                        String.format(
                                "%s:%s",
                                URLEncoder.encode(ocCredentials.getClientId(), "UTF-8"),
                                URLEncoder.encode(ocCredentials.getClientPassword().getPlainText(), "UTF-8")
                        ).getBytes(StandardCharsets.UTF_8)
                )
        ));

        requestBuilder.setUri("https://account.demandware.com/dwsso/oauth2/access_token");
        requestBuilder.setEntity(new UrlEncodedFormEntity(httpPostParams, Consts.UTF_8));

        CloseableHttpClient httpClient = getCloseableHttpClient();
        CloseableHttpResponse httpResponse;

        try {
            httpResponse = httpClient.execute(requestBuilder.build());
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        String httpEntityString;

        try {
            httpEntityString = EntityUtils.toString(httpResponse.getEntity(), "UTF-8");
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        try {
            httpResponse.close();
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        try {
            httpClient.close();
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while closing HTTP client!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        StatusLine httpStatusLine = httpResponse.getStatusLine();

        if (httpStatusLine.getStatusCode() != HttpStatus.SC_OK) {
            throw new AbortException(String.format(
                    "Failed to authenticate with OCAPI! %s - %s!\nResponse=%s",
                    httpStatusLine.getStatusCode(),
                    httpStatusLine.getReasonPhrase(),
                    httpEntityString
            ));
        }

        JsonElement jsonElement;

        try {
            JsonParser jsonParser = new JsonParser();
            jsonElement = jsonParser.parse(httpEntityString);
        } catch (JsonParseException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while parsing OCAPI JSON response!\nResponse=%s\n%s",
                    httpEntityString,
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        if (!jsonElement.isJsonObject()) {
            throw new AbortException(String.format(
                    "Failed to parse OCAPI JSON response!\nResponse=%s",
                    httpEntityString
            ));
        }

        JsonObject jsonObject = jsonElement.getAsJsonObject();
        boolean isValidJson = Stream.of("access_token", "token_type", "expires_in").allMatch(jsonObject::has);

        if (!isValidJson) {
            throw new AbortException(String.format(
                    "Failed to parse OCAPI JSON response!\nResponse=%s",
                    httpEntityString
            ));
        }

        String accessToken = jsonObject.get("access_token").getAsString();
        String tokenType = jsonObject.get("token_type").getAsString();
        long expiresIn = jsonObject.get("expires_in").getAsLong();

        cacheAuthToken = accessToken;
        cacheAuthType = tokenType;
        cacheAuthExpire = (new Date().getTime() / 1000L) + expiresIn - 60;

        return new AuthResponse(cacheAuthToken, cacheAuthType);
    }

    JobExecutionResult runJob() throws IOException {
        AuthResponse authResponse = auth();

        RequestBuilder requestBuilder = RequestBuilder.create("POST");
        requestBuilder.setHeader("Authorization", String.format(
                "%s %s",
                authResponse.getAuthType(),
                authResponse.getAuthToken()
        ));

        if (jobArguments != null && !jobArguments.isEmpty()) {
            JsonArray jobExecutionParameters = new JsonArray();
            jobArguments.forEach(jobArgument -> {
                JsonObject jobExecutionParameter = new JsonObject();
                jobExecutionParameter.addProperty("name", jobArgument.getName());
                jobExecutionParameter.addProperty("value", jobArgument.getValue());
                jobExecutionParameters.add(jobExecutionParameter);
            });

            JsonObject jobExecutionRequest = new JsonObject();
            jobExecutionRequest.add("parameters", jobExecutionParameters);
            requestBuilder.setEntity(new StringEntity(jobExecutionRequest.toString(), ContentType.APPLICATION_JSON));
        }

        requestBuilder.setUri(String.format(
                "https://%s/s/-/dw/data/%s/jobs/%s/executions?client_id=%s",
                hostname,
                URLEncoder.encode(ocVersion, "UTF-8"),
                URLEncoder.encode(jobName, "UTF-8"),
                URLEncoder.encode(ocCredentials.getClientId(), "UTF-8")
        ));

        CloseableHttpClient httpClient = getCloseableHttpClientWithCustomSSLSettings();
        CloseableHttpResponse httpResponse;

        try {
            httpResponse = httpClient.execute(requestBuilder.build());
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        String httpEntityString;

        try {
            httpEntityString = EntityUtils.toString(httpResponse.getEntity(), "UTF-8");
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        try {
            httpResponse.close();
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        try {
            httpClient.close();
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while closing HTTP client!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        JsonElement jsonElement;

        try {
            JsonParser jsonParser = new JsonParser();
            jsonElement = jsonParser.parse(httpEntityString);
        } catch (JsonParseException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while parsing OCAPI JSON response!\nResponse=%s\n%s",
                    httpEntityString,
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        StatusLine httpStatusLine = httpResponse.getStatusLine();

        if (!Arrays.asList(HttpStatus.SC_OK, HttpStatus.SC_ACCEPTED).contains(httpStatusLine.getStatusCode())) {
            throw new AbortException(String.format(
                    "Failed to execute OCAPI job! %s - %s!\nResponse=%s",
                    httpStatusLine.getStatusCode(),
                    httpStatusLine.getReasonPhrase(),
                    httpEntityString
            ));
        }

        if (!jsonElement.isJsonObject()) {
            throw new AbortException(String.format(
                    "Failed to parse OCAPI execute job JSON response!\nResponse=%s",
                    httpEntityString
            ));
        }

        JsonObject jsonObject = jsonElement.getAsJsonObject();
        boolean isValidJson = Stream.of("execution_status", "id").allMatch(jsonObject::has);

        if (!isValidJson) {
            throw new AbortException(String.format(
                    "Failed to parse OCAPI execute job JSON response!\nResponse=%s",
                    httpEntityString
            ));
        }

        String jobId = jsonObject.get("id").getAsString();
        String jobStatus = jsonObject.get("execution_status").getAsString();
        return new JobExecutionResult(jobId, jobStatus);
    }

    JobExecutionResult checkJob(String jobId) throws IOException {
        AuthResponse authResponse = auth();

        RequestBuilder requestBuilder = RequestBuilder.create("GET");
        requestBuilder.setHeader("Authorization", String.format(
                "%s %s",
                authResponse.getAuthType(),
                authResponse.getAuthToken()
        ));

        requestBuilder.setUri(String.format(
                "https://%s/s/-/dw/data/%s/jobs/%s/executions/%s?client_id=%s",
                hostname,
                URLEncoder.encode(ocVersion, "UTF-8"),
                URLEncoder.encode(jobName, "UTF-8"),
                URLEncoder.encode(jobId, "UTF-8"),
                URLEncoder.encode(ocCredentials.getClientId(), "UTF-8")
        ));

        CloseableHttpClient httpClient = getCloseableHttpClientWithCustomSSLSettings();
        CloseableHttpResponse httpResponse;

        try {
            httpResponse = httpClient.execute(requestBuilder.build());
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        String httpEntityString;

        try {
            httpEntityString = EntityUtils.toString(httpResponse.getEntity(), "UTF-8");
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        try {
            httpResponse.close();
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while making HTTP request!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        try {
            httpClient.close();
        } catch (IOException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while closing HTTP client!\n%s",
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        JsonElement jsonElement;

        try {
            JsonParser jsonParser = new JsonParser();
            jsonElement = jsonParser.parse(httpEntityString);
        } catch (JsonParseException e) {
            AbortException abortException = new AbortException(String.format(
                    "Exception thrown while parsing OCAPI JSON response!\nResponse=%s\n%s",
                    httpEntityString,
                    ExceptionUtils.getStackTrace(e)
            ));
            abortException.initCause(e);
            throw abortException;
        }

        StatusLine httpStatusLine = httpResponse.getStatusLine();

        if (httpStatusLine.getStatusCode() != HttpStatus.SC_OK) {
            throw new AbortException(String.format(
                    "Failed to get OCAPI job status! %s - %s!\nResponse=%s",
                    httpStatusLine.getStatusCode(),
                    httpStatusLine.getReasonPhrase(),
                    httpEntityString
            ));
        }

        if (!jsonElement.isJsonObject()) {
            throw new AbortException(String.format(
                    "Failed to parse OCAPI get job JSON response!\nResponse=%s",
                    httpEntityString
            ));
        }

        JsonObject jsonObject = jsonElement.getAsJsonObject();
        if (!jsonObject.has("execution_status")) {
            throw new AbortException(String.format(
                    "Failed to parse OCAPI get job JSON response!\nResponse=%s",
                    httpEntityString
            ));
        }

        JsonElement jsonExecutionStatus = jsonObject.get("execution_status");
        String executionStatus = jsonExecutionStatus.getAsString();

        if (StringUtils.equalsIgnoreCase(executionStatus, "finished")) {
            if (!jsonObject.has("exit_status")) {
                throw new AbortException(String.format(
                        "Failed to parse OCAPI get job JSON response!\nResponse=%s",
                        httpEntityString
                ));
            }

            JsonElement exitStatusElement = jsonObject.get("exit_status");

            if (!exitStatusElement.isJsonObject()) {
                throw new AbortException(String.format(
                        "Failed to parse OCAPI get job JSON response!\nResponse=%s",
                        httpEntityString
                ));
            }

            JsonObject exitStatusObject = exitStatusElement.getAsJsonObject();

            JsonElement exitStatusStatusElement = exitStatusObject.get("status");
            String exitStatusStatus = exitStatusStatusElement.getAsString();

            if (!StringUtils.equalsIgnoreCase(exitStatusStatus, "ok")) {
                throw new AbortException(String.format(
                        "Failed to run %s!\nResponse=%s",
                        jobName,
                        httpEntityString
                ));
            }
        }

        String jobStatus = jsonObject.get("execution_status").getAsString();
        return new JobExecutionResult(jobId, jobStatus);
    }

    private static final class AuthResponse {
        private String authToken;
        private String authType;

        AuthResponse(String authToken, String authType) {
            this.authToken = authToken;
            this.authType = authType;
        }

        String getAuthToken() {
            return authToken;
        }

        String getAuthType() {
            return authType;
        }
    }

    static final class JobExecutionResult {
        private String id;
        private String status;

        JobExecutionResult(String id, String status) {
            this.id = id;
            this.status = status;
        }

        String getId() {
            return id;
        }

        String getStatus() {
            return status;
        }
    }
}
