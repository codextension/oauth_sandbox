package net.khoury.elie.dao;

import net.khoury.elie.model.PersonalData;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

/**
 * Created by elie on 19.11.15.
 */
public interface PersonalDataRepository extends CrudRepository<PersonalData, Integer> {

    @Query("select concat(p.firstName, ' ', p.lastName)  from PersonalData p join p.user u where u.username=:username")
    String findNameByUsername(@Param("username") String username);

}
