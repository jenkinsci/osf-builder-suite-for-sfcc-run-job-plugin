package org.jenkinsci.plugins.osfbuildersuiteforsfcc.runjob.repeatable;

import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

public class JobArgument implements Serializable, Describable<JobArgument> {

    private final String name;
    private final String value;

    @DataBoundConstructor
    public JobArgument(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) Jenkins.get().getDescriptor(getClass());
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<JobArgument> {
        @Override
        public String getDisplayName() {
            return "OSF Builder Suite For Salesforce Commerce Cloud :: Run Job (JobArgument)";
        }
    }
}
