package net.khoury.elie.dao;

import net.khoury.elie.model.User;
import org.springframework.data.repository.CrudRepository;

/**
 * Created by elie on 19.11.15.
 */
public interface UserRepository extends CrudRepository<User, String> {

}
