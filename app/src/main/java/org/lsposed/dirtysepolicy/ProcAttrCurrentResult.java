package org.lsposed.dirtysepolicy;

final class ProcAttrCurrentResult {
    final boolean attempted;
    final String targetContext;
    final String outcomeClass;
    final String rawMessage;

    ProcAttrCurrentResult(boolean attempted, String targetContext, String outcomeClass, String rawMessage) {
        this.attempted = attempted;
        this.targetContext = targetContext;
        this.outcomeClass = outcomeClass;
        this.rawMessage = rawMessage;
    }

    static ProcAttrCurrentResult notRun(String targetContext) {
        return new ProcAttrCurrentResult(false, targetContext, "NOT_RUN", "probe did not run");
    }

    static ProcAttrCurrentResult success(String targetContext, String rawMessage) {
        return new ProcAttrCurrentResult(true, targetContext, "SUCCESS", rawMessage);
    }

    static ProcAttrCurrentResult einval(String targetContext, String rawMessage) {
        return new ProcAttrCurrentResult(true, targetContext, "NORMAL_EINVAL", rawMessage);
    }

    static ProcAttrCurrentResult nonEinval(String targetContext, String rawMessage) {
        return new ProcAttrCurrentResult(true, targetContext, "DETECTED_NON_EINVAL", rawMessage);
    }

    static ProcAttrCurrentResult security(String targetContext, String rawMessage) {
        return new ProcAttrCurrentResult(true, targetContext, "DETECTED_SECURITY_EXCEPTION", rawMessage);
    }

    boolean detected() {
        return attempted && !"NORMAL_EINVAL".equals(outcomeClass);
    }

    String formatMultiline(String prefix) {
        return prefix + " attempted=" + attempted + '\n'
                + prefix + " target=" + targetContext + '\n'
                + prefix + " class=" + outcomeClass + '\n'
                + prefix + " detected=" + detected() + '\n'
                + prefix + " raw=" + rawMessage;
    }
}
