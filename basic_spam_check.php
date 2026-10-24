<?php

/**
 * This is a deliberately modest spam check, not a general-purpose security filter.
 * It rejects malformed POST data and drops obvious React2Shell probes; it does not
 * protect vulnerable React Server Components. See the
 * [React advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
 * and [CVE-2025-55182](https://www.cve.org/CVERecord?id=CVE-2025-55182).
 */
function is_possible_spam(array $post): bool {
    $encodedPost = json_encode($post);

    // malformed input, consider it as spam
    if($encodedPost === false) {
        return true;
    }

    // discard React2Shell probes
    if(str_contains($encodedPost, 'resolved_model')) {
        return true;
    }

    return false;
}
