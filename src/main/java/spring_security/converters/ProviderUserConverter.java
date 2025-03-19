package spring_security.converters;

public interface ProviderUserConverter <T,R>{
    R converter(T t);
}
