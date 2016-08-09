package net.khoury.elie.model;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.Date;
import java.util.Set;

/**
 * Created by elie on 19.11.15.
 */
@Entity
@Table(name = "users")
public class User {
    @Id
    @NotNull
    @Column(name = "username", nullable = false, unique = true)
    private String username;

    @NotNull
    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private boolean enabled = true;

    @Version
    @Column(name = "changed")
    private Date changed;

    @OneToMany(mappedBy = "user", targetEntity = PersonalData.class)
    private Set<PersonalData> personalData;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Date getChanged() {
        return changed;
    }

    public Set<PersonalData> getPersonalData() {
        return personalData;
    }

    public void setPersonalData(Set<PersonalData> personalData) {
        this.personalData = personalData;
    }
}
