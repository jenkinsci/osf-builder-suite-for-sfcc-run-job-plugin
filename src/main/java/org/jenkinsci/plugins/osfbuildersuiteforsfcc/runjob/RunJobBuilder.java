package org.jenkinsci.plugins.osfbuildersuiteforsfcc.runjob;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.URIRequirementBuilder;
import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.model.queue.Tasks;
import hudson.remoting.VirtualChannel;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.ListBoxModel;
import jenkins.MasterToSlaveFileCallable;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.HTTPProxyCredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.credentials.OpenCommerceAPICredentials;
import org.jenkinsci.plugins.osfbuildersuiteforsfcc.runjob.repeatable.JobArgument;
import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;
import org.kohsuke.stapler.*;

import javax.annotation.Nonnull;
import java.io.*;
import java.util.List;
import java.util.concurrent.TimeUnit;


@SuppressWarnings("unused")
public class RunJobBuilder extends Builder implements SimpleBuildStep {

    private String hostname;
    private String ocCredentialsId;
    private String ocVersion;
    private String jobName;
    private List<JobArgument> jobArguments;

    @DataBoundConstructor
    public RunJobBuilder(
            String hostname,
            String ocCredentialsId,
            String ocVersion,
            String jobName,
            List<JobArgument> jobArguments) {

        this.hostname = hostname;
        this.ocCredentialsId = ocCredentialsId;
        this.ocVersion = ocVersion;
        this.jobName = jobName;
        this.jobArguments = jobArguments;
    }

    @SuppressWarnings("unused")
    public String getHostname() {
        return hostname;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    @SuppressWarnings("unused")
    public String getOcCredentialsId() {
        return ocCredentialsId;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setOcCredentialsId(String ocCredentialsId) {
        this.ocCredentialsId = ocCredentialsId;
    }

    @SuppressWarnings("unused")
    public String getOcVersion() {
        return ocVersion;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setOcVersion(String ocVersion) {
        this.ocVersion = ocVersion;
    }

    @SuppressWarnings("unused")
    public String getJobName() {
        return jobName;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setJobName(String jobName) {
        this.jobName = jobName;
    }

    @SuppressWarnings("unused")
    public List<JobArgument> getJobArguments() {
        return jobArguments;
    }

    @SuppressWarnings("unused")
    @DataBoundSetter
    public void setJobArguments(List<JobArgument> jobArguments) {
        this.jobArguments = jobArguments;
    }

    @Override
    public void perform(
            @Nonnull Run<?, ?> build,
            @Nonnull FilePath workspace,
            @Nonnull Launcher launcher,
            @Nonnull TaskListener listener) throws InterruptedException, IOException {

        PrintStream logger = listener.getLogger();

        logger.println();
        logger.println(String.format("--[B: %s]--", getDescriptor().getDisplayName()));
        logger.println();

        String expandedHostname;
        try {
            expandedHostname = TokenMacro.expandAll(build, workspace, listener, hostname);
        } catch (MacroEvaluationException e) {
            AbortException abortException = new AbortException("Exception thrown while expanding the hostname!");
            abortException.initCause(e);
            throw abortException;
        }

        OpenCommerceAPICredentials ocCredentials = null;
        if (StringUtils.isNotEmpty(ocCredentialsId)) {
            ocCredentials = com.cloudbees.plugins.credentials.CredentialsProvider.findCredentialById(
                    ocCredentialsId,
                    OpenCommerceAPICredentials.class,
                    build, URIRequirementBuilder.create().build()
            );
        }

        if (ocCredentials != null) {
            com.cloudbees.plugins.credentials.CredentialsProvider.track(build, ocCredentials);
        }

        HTTPProxyCredentials httpProxyCredentials = null;
        if (StringUtils.isNotEmpty(getDescriptor().getHttpProxyCredentialsId())) {
            httpProxyCredentials = com.cloudbees.plugins.credentials.CredentialsProvider.findCredentialById(
                    getDescriptor().getHttpProxyCredentialsId(),
                    HTTPProxyCredentials.class,
                    build,
                    URIRequirementBuilder.create().build()
            );
        }

        workspace.act(new RunJobCallable(
                listener,
                expandedHostname,
                ocCredentialsId,
                ocCredentials,
                ocVersion,
                jobName,
                jobArguments,
                httpProxyCredentials,
                getDescriptor().getDisableSSLValidation()
        ));

        logger.println();
        logger.println(String.format("--[E: %s]--", getDescriptor().getDisplayName()));
        logger.println();
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    @Extension
    @Symbol("osfBuilderSuiteForSFCCRunJob")
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        private String httpProxyCredentialsId;
        private Boolean disableSSLValidation;

        public DescriptorImpl() {
            load();
        }

        public String getDisplayName() {
            return "OSF Builder Suite For Salesforce Commerce Cloud :: Run Job";
        }

        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillOcCredentialsIdItems(
                @AncestorInPath Item item,
                @QueryParameter String credentialsId) {

            StandardListBoxModel result = new StandardListBoxModel();

            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(credentialsId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(credentialsId);
                }
            }

            return result
                    .includeEmptyValue()
                    .includeMatchingAs(
                            item instanceof hudson.model.Queue.Task
                                    ? Tasks.getAuthenticationOf((hudson.model.Queue.Task) item)
                                    : ACL.SYSTEM,
                            item,
                            StandardCredentials.class,
                            URIRequirementBuilder.create().build(),
                            CredentialsMatchers.instanceOf(OpenCommerceAPICredentials.class)
                    )
                    .includeCurrentValue(credentialsId);
        }

        @SuppressWarnings("unused")
        public ListBoxModel doFillHttpProxyCredentialsIdItems(
                @AncestorInPath Item item,
                @QueryParameter String credentialsId) {

            StandardListBoxModel result = new StandardListBoxModel();

            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(credentialsId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ)
                        && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return result.includeCurrentValue(credentialsId);
                }
            }

            return result
                    .includeEmptyValue()
                    .includeMatchingAs(
                            item instanceof hudson.model.Queue.Task
                                    ? Tasks.getAuthenticationOf((hudson.model.Queue.Task) item)
                                    : ACL.SYSTEM,
                            item,
                            StandardCredentials.class,
                            URIRequirementBuilder.create().build(),
                            CredentialsMatchers.instanceOf(HTTPProxyCredentials.class)
                    )
                    .includeCurrentValue(credentialsId);
        }

        @SuppressWarnings("WeakerAccess")
        public String getHttpProxyCredentialsId() {
            return httpProxyCredentialsId;
        }

        @SuppressWarnings("unused")
        public void setHttpProxyCredentialsId(String httpProxyCredentialsId) {
            this.httpProxyCredentialsId = httpProxyCredentialsId;
        }

        @SuppressWarnings("WeakerAccess")
        public Boolean getDisableSSLValidation() {
            return disableSSLValidation;
        }

        @SuppressWarnings("unused")
        public void setDisableSSLValidation(Boolean disableSSLValidation) {
            this.disableSSLValidation = disableSSLValidation;
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
            httpProxyCredentialsId = formData.getString("httpProxyCredentialsId");
            disableSSLValidation = formData.getBoolean("disableSSLValidation");

            save();

            return super.configure(req, formData);
        }
    }

    private static class RunJobCallable extends MasterToSlaveFileCallable<Void> {

        private static final long serialVersionUID = 1L;

        private final TaskListener listener;
        private final String hostname;
        private final String ocCredentialsId;
        private final OpenCommerceAPICredentials ocCredentials;
        private final String ocVersion;
        private final String jobName;
        private final List<JobArgument> jobArguments;
        private final HTTPProxyCredentials httpProxyCredentials;
        private final Boolean disableSSLValidation;

        @SuppressWarnings("WeakerAccess")
        public RunJobCallable(
                TaskListener listener,
                String hostname,
                String ocCredentialsId,
                OpenCommerceAPICredentials ocCredentials,
                String ocVersion,
                String jobName,
                List<JobArgument> jobArguments,
                HTTPProxyCredentials httpProxyCredentials,
                Boolean disableSSLValidation) {

            this.listener = listener;
            this.hostname = hostname;
            this.ocCredentialsId = ocCredentialsId;
            this.ocCredentials = ocCredentials;
            this.ocVersion = ocVersion;
            this.jobName = jobName;
            this.jobArguments = jobArguments;
            this.httpProxyCredentials = httpProxyCredentials;
            this.disableSSLValidation = disableSSLValidation;
        }

        @Override
        public Void invoke(File dir, VirtualChannel channel) throws IOException, InterruptedException {
            PrintStream logger = listener.getLogger();

            if (StringUtils.isEmpty(hostname)) {
                logger.println();
                throw new AbortException(
                        "Missing value for \"Instance Hostname\"!" + " " +
                                "What are we going to do with all the data if we don't have where to push it?"
                );
            }

            if (StringUtils.isEmpty(ocCredentialsId)) {
                logger.println();
                throw new AbortException(
                        "Missing \"Open Commerce API Credentials\"!" + " " +
                                "We can't import the data without proper credentials, can't we?"
                );
            }

            if (ocCredentials == null) {
                logger.println();
                throw new AbortException(
                        "Failed to load \"Open Commerce API Credentials\"!" + " " +
                                "Something's wrong but not sure who's blame it is..."
                );
            }

            if (StringUtils.isEmpty(ocVersion)) {
                logger.println();
                throw new AbortException(
                        "Missing \"Open Commerce API Version\"!" + " " +
                                "We can't use Open Commerce API without specifying a version, can't we?"
                );
            }

            if (StringUtils.isEmpty(jobName)) {
                logger.println();
                throw new AbortException(
                        "Missing \"Job Name\"!" + " " +
                                "We can't run a job if we don't know its name!"
                );
            }

            OpenCommerceAPI openCommerceAPI = new OpenCommerceAPI(
                    hostname,
                    httpProxyCredentials,
                    disableSSLValidation,
                    ocCredentials,
                    ocVersion,
                    jobName,
                    jobArguments
            );

            /* Running job */
            logger.println();
            logger.println(String.format("[+] Running %s", jobName));

            OpenCommerceAPI.JobExecutionResult runJobResult = openCommerceAPI.runJob();
            logger.println(String.format(" - %s", runJobResult.getStatus()));

            String currentExecutionStatus = runJobResult.getStatus();
            while (!StringUtils.equalsIgnoreCase(currentExecutionStatus, "finished")) {
                TimeUnit.MINUTES.sleep(1);
                OpenCommerceAPI.JobExecutionResult chkJobResult = openCommerceAPI.checkJob(runJobResult.getId());
                currentExecutionStatus = chkJobResult.getStatus();
                logger.println(String.format(" - %s", currentExecutionStatus));
            }

            logger.println(" + Ok");
            /* Running job */

            return null;
        }
    }
}
