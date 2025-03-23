package spring_security.common.converters;

public interface ProviderUserConverter <T,R>{
    R converter(T t);
}
