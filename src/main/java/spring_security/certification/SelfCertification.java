package spring_security.certification;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import spring_security.model.ProviderUser;
import spring_security.model.users.User;
import spring_security.repository.UserRepository;

@Component
@RequiredArgsConstructor
public class SelfCertification {

    private final UserRepository userRepository;

    public void checkCertification(ProviderUser providerUser) {
        User user = userRepository.findByUsername(providerUser.getId());
        boolean bool = providerUser.equals("none") || providerUser.getProvider().equals("naver");
        providerUser.isCertificated(bool);
    }

    public void certificate(ProviderUser providerUser) {

    }
}
